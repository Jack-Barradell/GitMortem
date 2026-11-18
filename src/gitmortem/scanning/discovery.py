import os
import stat
import sys
import threading
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.db.models import (
    DeletionState,
    DiscoveryRun,
    Repository,
    RepositoryKind,
    RepositoryRefusal,
    RepositoryState,
    ScanRoot,
    utcnow,
)
from gitmortem.gitrun import GitCancelled, GitError, GitRunner
from gitmortem.scanning import roots
from gitmortem.scanning.repos import RepoFacts, display_path, inspect_repo
from gitmortem.scanning.roots import Identity, SkippedFolders

_GITFILE_MAX = 8192
_GITFILE_PREFIX = b"gitdir: "
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


class NotFollowedReason(StrEnum):
    SYMLINK = "symlink"
    GIT_LINK = "git_link"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Found:
    rel_path: bytes
    display_path: str
    git_dir: Path
    kind: RepositoryKind
    org: str | None
    name: str
    refusal: RepositoryRefusal | None = None


@dataclass(frozen=True)
class Alias:
    rel_path: bytes


@dataclass(frozen=True)
class NotFollowed:
    rel_path: bytes
    reason: NotFollowedReason = NotFollowedReason.SYMLINK


Walked = Found | Alias | NotFollowed


@dataclass(frozen=True)
class Seen:
    found: Found
    facts: RepoFacts
    at: datetime = field(default_factory=utcnow)


Event = Seen | Alias | NotFollowed


class DiscoveryCancelled(Exception):
    def __init__(self) -> None:
        super().__init__("discovery was cancelled")


def _join(rel: bytes, name: bytes) -> bytes:
    return rel + b"/" + name if rel else name


def _names(rel: bytes, root: Path, kind: RepositoryKind) -> tuple[str | None, str]:
    parent, _, name = rel.rpartition(b"/")
    if not rel:
        name = os.fsencode(root.name)
    if kind is RepositoryKind.BARE and name.endswith(b".git") and len(name) > len(b".git"):
        name = name.removesuffix(b".git")
    return (display_path(parent) if parent else None), display_path(name)


def _is_link(entry: os.DirEntry[bytes]) -> bool:
    try:
        return roots.is_link(entry)
    except OSError:
        return False


def _leads_to_folder(entry: os.DirEntry[bytes], root: Path) -> bool:
    try:
        real = roots.real_inside(Path(os.fsdecode(entry.path)), root)
        if real is not None:
            return real.is_dir()
        if sys.platform == "win32":
            return entry.is_junction() or entry.is_dir(follow_symlinks=False)
        return entry.is_dir(follow_symlinks=True)
    except (OSError, ValueError):
        return False


def _is_dir(entry: os.DirEntry[bytes]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _is_file(entry: os.DirEntry[bytes]) -> bool:
    try:
        return entry.is_file(follow_symlinks=False)
    except OSError:
        return False


def _plain_files(folder: bytes) -> bool:
    for name, needed in ((b"HEAD", True), (b"config", False)):
        try:
            found = os.lstat(os.path.join(folder, name))
        except FileNotFoundError:
            if needed:
                return False
            continue
        except OSError:
            return False
        if not stat.S_ISREG(found.st_mode):
            return False
    return True


def _gitfile_target(path: bytes) -> bytes | None:
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, _GITFILE_MAX + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > _GITFILE_MAX or not data.startswith(_GITFILE_PREFIX):
        return None
    target = data[len(_GITFILE_PREFIX) :].rstrip(b"\r\n")
    return target if target and b"\0" not in target else None


@dataclass(frozen=True)
class _Folder:
    rel: bytes
    path: bytes
    ident: Identity | None
    parent: "_Folder | None"

    def descends_from(self, ident: Identity) -> bool:
        node: _Folder | None = self
        while node is not None:
            if node.ident == ident:
                return True
            node = node.parent
        return False


class _Walk:
    def __init__(
        self, runner: GitRunner, root: Path, skip: Collection[Path], cancel: threading.Event
    ) -> None:
        self.runner = runner
        self.root = root
        self.skip = SkippedFolders(skip)
        self.cancel = cancel
        self.claimed: set[Identity | bytes] = set()
        self.unclaimed: list[tuple[bytes, Path]] = []
        self.gitfiles: list[tuple[bytes, bytes, bytes]] = []

    def run(self) -> Iterator[Walked]:
        if self.skip.covers(self.root):
            raise ValueError("the scan root is inside a folder discovery skips")
        top = os.fsencode(self.root)
        pending = [_Folder(b"", top, roots.folder_identity(top), None)]
        while pending:
            if self.cancel.is_set():
                raise DiscoveryCancelled
            folder = pending.pop()
            rel, here = folder.rel, folder.path
            try:
                with os.scandir(here) as listing:
                    entries = sorted(listing, key=lambda entry: entry.name)
            except OSError:
                if not rel:
                    raise
                yield NotFollowed(rel, NotFollowedReason.UNREADABLE)
                continue
            by_name = {entry.name: entry for entry in entries}
            found, enter = self._repo_at(rel, here, by_name)
            if found is not None:
                yield found
            if not enter:
                continue
            folders = []
            for entry in entries:
                child = _join(rel, entry.name)
                if _is_link(entry):
                    if entry.name == b".git":
                        yield NotFollowed(child, NotFollowedReason.GIT_LINK)
                    elif _leads_to_folder(entry, self.root):
                        yield NotFollowed(child)
                    continue
                if entry.name == b".git" or not _is_dir(entry):
                    continue
                ident = roots.folder_identity(entry.path)
                if self.skip.is_skipped(Path(os.fsdecode(entry.path)), ident):
                    continue
                if ident is not None and folder.descends_from(ident):
                    continue
                folders.append(_Folder(child, entry.path, ident, folder))
            pending.extend(reversed(folders))
        for rel, here, gitfile in self.gitfiles:
            yield self._gitfile(rel, here, gitfile)
        for rel, git_dir in self.unclaimed:
            yield self._git_dir(rel, git_dir, RepositoryKind.BARE)

    def _repo_at(
        self, rel: bytes, here: bytes, by_name: dict[bytes, os.DirEntry[bytes]]
    ) -> tuple[Walked | None, bool]:
        dot_git = by_name.get(b".git")
        if dot_git is not None and not _is_link(dot_git):
            if _is_dir(dot_git):
                return self._git_dir(
                    rel, Path(os.fsdecode(dot_git.path)), RepositoryKind.WORK_TREE
                ), True
            if _is_file(dot_git):
                self.gitfiles.append((rel, here, dot_git.path))
                return None, True
        if self._looks_like_git_dir(by_name):
            bare = self._is_bare(here)
            path = Path(os.fsdecode(here))
            if bare:
                return self._git_dir(rel, path, RepositoryKind.BARE), False
            if bare is False:
                self.unclaimed.append((rel, path))
                return None, False
            if not self._enterable(by_name):
                return NotFollowed(rel, NotFollowedReason.UNREADABLE), False
        return None, True

    @staticmethod
    def _looks_like_git_dir(by_name: dict[bytes, os.DirEntry[bytes]]) -> bool:
        head, objects, refs = (by_name.get(name) for name in (b"HEAD", b"objects", b"refs"))
        return (
            head is not None
            and (_is_file(head) or _is_link(head))
            and objects is not None
            and _is_dir(objects)
            and refs is not None
            and _is_dir(refs)
        )

    @staticmethod
    def _enterable(by_name: dict[bytes, os.DirEntry[bytes]]) -> bool:
        try:
            by_name[b"HEAD"].stat(follow_symlinks=False)
        except OSError:
            return False
        return True

    def _is_bare(self, folder: bytes) -> bool | None:
        if not _plain_files(folder):
            return None
        named = os.fsdecode(folder)
        try:
            out = self.runner.run(
                ["rev-parse", "--is-bare-repository"],
                cwd=self.runner.private_dir,
                extra_env={"GIT_DIR": named, "GIT_COMMON_DIR": named},
                cancel=self.cancel,
            )
        except GitCancelled:
            raise DiscoveryCancelled from None
        except GitError:
            return None
        return out.strip() == b"true"

    def _claim(self, git_dir: Path) -> bool:
        spelled = os.fsencode(git_dir)
        keys: set[Identity | bytes] = {spelled}
        if (ident := roots.folder_identity(spelled)) is not None:
            keys.add(ident)
        if keys & self.claimed:
            return False
        self.claimed |= keys
        return True

    def _found(
        self,
        rel: bytes,
        git_dir: Path,
        kind: RepositoryKind,
        refusal: RepositoryRefusal | None = None,
    ) -> Walked:
        if not self._claim(git_dir):
            return Alias(rel)
        org, name = _names(rel, self.root, kind)
        return Found(
            rel_path=rel,
            display_path=display_path(rel) if rel else ".",
            git_dir=git_dir,
            kind=kind,
            org=org,
            name=name,
            refusal=refusal,
        )

    def _git_dir(self, rel: bytes, git_dir: Path, kind: RepositoryKind) -> Walked:
        try:
            os.lstat(git_dir / "commondir")
        except (FileNotFoundError, NotADirectoryError):
            return self._found(rel, git_dir, kind)
        except OSError:
            return self._found(rel, git_dir, kind, RepositoryRefusal.UNREADABLE)
        return Alias(rel)

    def _gitfile(self, rel: bytes, here: bytes, gitfile: bytes) -> Walked:
        named = _gitfile_target(gitfile)
        own = Path(os.fsdecode(gitfile))
        if named is None:
            return self._found(rel, own, RepositoryKind.WORK_TREE, RepositoryRefusal.UNREADABLE)
        target = Path(os.fsdecode(named))
        if not target.is_absolute():
            target = Path(os.fsdecode(here)) / target
        try:
            real = roots.real_inside(target, self.root)
            if real is None or self.skip.covers(real):
                return self._found(
                    rel, own, RepositoryKind.WORK_TREE, RepositoryRefusal.OUTSIDE_ROOT
                )
            target = real
            is_dir = target.is_dir()
        except (OSError, RuntimeError, ValueError):
            return self._found(rel, own, RepositoryKind.WORK_TREE, RepositoryRefusal.UNREADABLE)
        if not is_dir:
            return self._found(rel, own, RepositoryKind.WORK_TREE, RepositoryRefusal.UNREADABLE)
        return self._git_dir(rel, target, RepositoryKind.WORK_TREE)


def discover(
    runner: GitRunner, root: Path, *, skip: Collection[Path], cancel: threading.Event
) -> Iterator[Walked]:
    return _Walk(runner, root.resolve(strict=True), skip, cancel).run()


def discover_and_inspect(
    runner: GitRunner, root: Path, *, skip: Collection[Path], cancel: threading.Event
) -> Iterator[Event]:
    root = root.resolve(strict=True)
    for walked in discover(runner, root, skip=skip, cancel=cancel):
        if not isinstance(walked, Found):
            yield walked
            continue
        started = utcnow()
        if walked.refusal is not None:
            facts = RepoFacts.refused(walked.refusal)
        else:
            try:
                facts = inspect_repo(runner, walked.git_dir, root, skip=skip, cancel=cancel)
            except GitCancelled:
                raise DiscoveryCancelled from None
        yield Seen(walked, facts, started)


def _reappeared(row: Repository, seen: Seen) -> bool:
    if row.deleted_at is not None and seen.at <= row.deleted_at:
        return False
    return os.path.lexists(seen.found.git_dir)


class DiscoveryRecorder:
    def __init__(self, discovery_id: int, scan_root_id: int) -> None:
        self.discovery_id = discovery_id
        self.scan_root_id = scan_root_id
        self.seen: set[int] = set()
        self.unread: list[bytes] = []

    def record(self, session: Session, events: Iterable[Event], *, now: datetime) -> None:
        run = session.get(DiscoveryRun, self.discovery_id)
        if run is None:
            raise LookupError(f"no discovery run {self.discovery_id}")
        for event in events:
            if isinstance(event, Alias):
                run.aliases += 1
            elif isinstance(event, NotFollowed):
                run.not_followed += 1
                if event.reason is NotFollowedReason.UNREADABLE:
                    self.unread.append(event.rel_path)
            elif (repo := self._upsert(session, event, now)) is None:
                run.aliases += 1
            else:
                run.found += 1
                if repo.state is RepositoryState.REFUSED:
                    run.refused += 1
        session.flush()

    def finish(self, session: Session) -> int:
        missing = 0
        rows = session.scalars(
            select(Repository).where(
                Repository.scan_root_id == self.scan_root_id,
                Repository.state != RepositoryState.MISSING,
                Repository.deletion_state.is_(None),
            )
        ).all()
        for repo in rows:
            if repo.id not in self.seen and not self._under_unread(repo.rel_path):
                repo.state = RepositoryState.MISSING
                repo.refusal = None
                missing += 1
        session.flush()
        return missing

    def _under_unread(self, rel: bytes | None) -> bool:
        if rel is None:
            return False
        return any(rel == folder or rel.startswith(folder + b"/") for folder in self.unread)

    def _has_moved(self, session: Session, holder: Repository) -> bool:
        if holder.scan_root_id == self.scan_root_id or holder.state is RepositoryState.MISSING:
            return True
        owner = session.get(ScanRoot, holder.scan_root_id)
        return owner is not None and owner.removed_at is not None

    def _upsert(self, session: Session, seen: Seen, now: datetime) -> Repository | None:
        found, facts = seen.found, seen.facts
        git_dir = os.fsencode(found.git_dir)
        here = session.scalars(
            select(Repository).where(
                Repository.scan_root_id == self.scan_root_id,
                Repository.rel_path == found.rel_path,
            )
        ).one_or_none()
        holder = session.scalars(
            select(Repository).where(Repository.git_dir == git_dir)
        ).one_or_none()
        if holder is not None and holder is not here:
            if here is not None or holder.id in self.seen or not self._has_moved(session, holder):
                return None
            here = holder
        if here is not None and here.deletion_state is not None:
            if here.deletion_state is not DeletionState.DELETED or not _reappeared(here, seen):
                self.seen.add(here.id)
                return None
            here.deletion_state = None
            here.deletion_failure = None
            here.deletion_id = None
            here.deleted_at = None
            here.first_seen_at = now
        if here is None:
            here = Repository(first_seen_at=now)
            session.add(here)
        here.scan_root_id = self.scan_root_id
        here.rel_path = found.rel_path
        here.display_path = found.display_path
        here.org = found.org
        here.name = found.name
        here.kind = found.kind
        here.git_dir = git_dir
        here.state = RepositoryState.SCANNABLE if facts.refusal is None else RepositoryState.REFUSED
        here.refusal = facts.refusal
        here.commit_count = facts.commit_count
        here.size_bytes = facts.size_bytes
        here.head = facts.head
        here.last_seen_at = now
        session.flush()
        self.seen.add(here.id)
        return here
