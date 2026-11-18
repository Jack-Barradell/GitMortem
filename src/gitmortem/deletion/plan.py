import hashlib
import json
import os
import stat
import time
from collections.abc import Collection
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from gitmortem.config import Settings, guarded_key_file
from gitmortem.db.models import (
    DeletionState,
    Finding,
    Note,
    Repository,
    RepositoryKind,
    RepositoryVersion,
    ScanRoot,
    StatusChange,
)
from gitmortem.gitrun import GitRunner
from gitmortem.scanning.repos import WALK_SECONDS, contained_git_dir
from gitmortem.scanning.roots import (
    containing_base,
    is_within,
    root_is_usable,
    spelled_within,
)
from gitmortem.uploads.place import repos_dir

MAX_DELETE_REPOSITORIES = 10_000
POINTER_MAX = 4096
_POINTER = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


class LeftReason(StrEnum):
    ROOT_REMOVED = "root_removed"
    ROOT_UNUSABLE = "root_unusable"
    NOT_CONTAINED = "not_contained"
    HOLDS_DATA_OR_KEY = "holds_data_or_key"
    WORKTREE_UNCONFIRMED = "worktree_unconfirmed"
    SEPARATE_GIT_DIR = "separate_git_dir"


@dataclass(frozen=True)
class Removal:
    root: Path
    rel: bytes
    keep_top: bool
    repository_id: int
    base: Path
    identity: tuple[int, int] | None
    covers: tuple[int, ...] = ()

    @property
    def display(self) -> str:
        return str(self.root / os.fsdecode(self.rel)) if self.rel else str(self.root)


@dataclass(frozen=True)
class LeftFolder:
    display: str
    reason: LeftReason


@dataclass(frozen=True)
class Counts:
    repositories: int
    findings: int
    secrets: int
    with_triage: int


@dataclass(frozen=True)
class DeletionPlan:
    repositories: tuple[int, ...]
    removals: tuple[Removal, ...]
    left: tuple[LeftFolder, ...]
    counts: Counts
    busy: tuple[int, ...] = ()


def plan_digest(plan: DeletionPlan) -> str:
    shown = {
        "repositories": sorted(plan.repositories),
        "removals": sorted(
            [
                str(removal.base),
                str(removal.root),
                removal.rel.hex(),
                removal.keep_top,
                removal.repository_id,
                list(removal.identity or ()),
                sorted(removal.covers),
            ]
            for removal in plan.removals
        ),
        "left": sorted([folder.display, folder.reason.value] for folder in plan.left),
    }
    return hashlib.sha256(json.dumps(shown, sort_keys=True).encode()).hexdigest()


def _rel(path: Path, root: Path) -> bytes | None:
    if not spelled_within(path, root):
        return None
    return os.fsencode(path.relative_to(root).as_posix()) if path != root else b""


def _holds(folder: Path, guarded: Collection[Path]) -> bool:
    return any(is_within(g, folder) for g in guarded)


def _identity(folder: Path) -> tuple[int, int] | None:
    try:
        found = os.stat(folder, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISDIR(found.st_mode) or found.st_ino == 0:
        return None
    return found.st_dev, found.st_ino


def read_pointer(path: Path) -> str | None:
    try:
        fd = os.open(path, _POINTER)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, POINTER_MAX + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > POINTER_MAX or b"\0" in data:
        return None
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


def _lexically_inside(named: str, folder: Path, root: Path) -> Path | None:
    if not named or named.startswith(("\\\\", "//")):
        return None
    joined = Path(named) if os.path.isabs(named) else folder / named
    spelled = Path(os.path.normpath(joined))
    return spelled if spelled_within(spelled, root) else None


def _worktrees(git_dir: Path, root: Path) -> list[tuple[str, Path | None]]:
    found: list[tuple[str, Path | None]] = []
    try:
        entries = sorted(os.scandir(git_dir / "worktrees"), key=lambda e: e.name)
    except OSError:
        return found
    for entry in entries:
        try:
            plain = not entry.is_symlink() and not entry.is_junction()
            plain = plain and entry.is_dir(follow_symlinks=False)
        except OSError:
            plain = False
        pointer = read_pointer(Path(entry.path) / "gitdir") if plain else None
        if pointer is None:
            found.append((entry.name, None))
            continue
        named = _lexically_inside(pointer, Path(entry.path), root)
        found.append((entry.name, None if named is None else named.parent))
    return found


def _points_back(folder: Path, git_dir: Path, worktree_id: str, root: Path) -> bool:
    entry = git_dir / "worktrees" / worktree_id
    common = read_pointer(entry / "commondir")
    if common is None or _lexically_inside(common, entry, root) != git_dir:
        return False
    content = read_pointer(folder / ".git")
    if content is None or not content.startswith("gitdir:"):
        return False
    target = _lexically_inside(content[len("gitdir:") :].strip(), folder, root)
    return target is not None and target.resolve() == entry


def _counts(session: Session, ids: Collection[int]) -> Counts:
    inside = Finding.repository_id.in_(ids)
    findings = session.scalar(select(func.count()).select_from(Finding).where(inside)) or 0
    present = select(Finding.secret_id).distinct().where(Finding.secret_id.is_not(None))
    doomed = set(session.scalars(present.where(inside))) - set(
        session.scalars(present.where(Finding.repository_id.not_in(ids)))
    )
    standalone = set(session.scalars(select(Finding.id).where(inside, Finding.secret_id.is_(None))))
    marked_secrets: set[int | None] = set()
    marked_findings: set[int | None] = set()
    for model in (StatusChange, Note):
        marked_secrets |= set(
            session.scalars(select(model.secret_id).distinct().where(model.secret_id.in_(doomed)))
        )
        marked_findings |= set(
            session.scalars(
                select(model.finding_id).distinct().where(model.finding_id.in_(standalone))
            )
        )
    return Counts(len(ids), findings, len(doomed), len(marked_secrets) + len(marked_findings))


def _known_inside(session: Session, root_id: int, rel: bytes) -> list[int]:
    return list(
        session.scalars(
            select(Repository.id).where(
                Repository.scan_root_id == root_id,
                or_(
                    Repository.deletion_state.is_(None),
                    Repository.deletion_state != DeletionState.DELETED,
                ),
                or_(
                    Repository.rel_path == rel,
                    func.substr(Repository.rel_path, 1, len(rel) + 1) == rel + b"/",
                ),
            )
        )
    )


def _confirmed_worktree(
    git_dir: Path, worktree_id: str, pointed: Path | None, root: Path
) -> bytes | None:
    if pointed is None:
        return None
    try:
        if _is_link(pointed) or not pointed.is_dir() or pointed.resolve() != pointed:
            return None
        if not _points_back(pointed, git_dir, worktree_id, root):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return _rel(pointed, root) or None


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _separate_git_dir_allowed(git_dir: Path, folder: Path, root: Path) -> bool:
    if not any(
        spelled_within(git_dir, ancestor / ".git" / "modules") for ancestor in folder.parents
    ):
        return False
    named = _module_worktree(git_dir)
    if named is None:
        return False
    target = _lexically_inside(named, git_dir, root)
    return target is not None and target.resolve() == folder


def _module_worktree(git_dir: Path) -> str | None:
    text = read_pointer(git_dir / "config")
    if text is None:
        return None
    section = ""
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                return None
            section = line[1:-1].strip().lower()
            if section.split(" ", 1)[0].split(".", 1)[0].startswith("include"):
                return None
            continue
        key, equals, value = line.partition("=")
        if section == "core" and key.strip().lower() == "worktree":
            value = value.strip()
            if not equals or not value or any(c in value for c in '"\\;#'):
                return None
            found.append(value)
    return found[0] if len(found) == 1 else None


def plan_deletion(
    session: Session,
    runner: GitRunner,
    settings: Settings,
    repository_ids: Collection[int],
    *,
    deletion_id: int | None = None,
) -> DeletionPlan:
    data_dir = settings.data_dir
    key_file = guarded_key_file(settings)
    guarded = [data_dir.resolve(), *([key_file.resolve()] if key_file is not None else [])]
    wanted = list(dict.fromkeys(repository_ids))
    removals: list[Removal] = []
    left: list[LeftFolder] = []
    seen: set[int] = set()
    busy: set[int] = set()
    while wanted:
        repo_id = wanted.pop(0)
        if repo_id in seen:
            continue
        repo = session.get(Repository, repo_id)
        if repo is None or repo.deletion_state is DeletionState.DELETED:
            continue
        if repo.deletion_state is DeletionState.DELETING and (
            deletion_id is None or repo.deletion_id != deletion_id
        ):
            busy.add(repo_id)
        seen.add(repo_id)
        if repo.kind is RepositoryKind.NOT_ON_DISK:
            continue
        if repo.kind is RepositoryKind.UPLOADED:
            area = repos_dir(data_dir).resolve()
            own = area / str(repo_id)
            if os.path.lexists(own):
                removals.append(
                    Removal(area, os.fsencode(str(repo_id)), False, repo_id, area, _identity(area))
                )
            for stored in session.scalars(
                select(RepositoryVersion.git_dir).where(RepositoryVersion.repository_id == repo_id)
            ):
                version = Path(os.fsdecode(stored))
                if not os.path.lexists(version) or spelled_within(version, own):
                    continue
                rel = _rel(version, area)
                if rel:
                    removals.append(Removal(area, rel, False, repo_id, area, _identity(area)))
                else:
                    left.append(LeftFolder(str(version), LeftReason.NOT_CONTAINED))
            continue
        root_row = session.get(ScanRoot, repo.scan_root_id) if repo.scan_root_id else None
        folder_rel = repo.rel_path or b""
        if root_row is None or repo.git_dir is None:
            continue
        root = Path(root_row.path)
        folder = root / os.fsdecode(folder_rel) if folder_rel else root
        if root_row.removed_at is not None:
            left.append(LeftFolder(str(folder), LeftReason.ROOT_REMOVED))
            continue
        base = containing_base(root, settings.scan_root_bases)
        if (
            base is None
            or not root_is_usable(
                root, bases=settings.scan_root_bases, data_dir=data_dir, key_file=key_file
            )
            or root.resolve() != root
        ):
            left.append(LeftFolder(str(folder), LeftReason.ROOT_UNUSABLE))
            continue
        git_dir = Path(os.fsdecode(repo.git_dir))
        real = contained_git_dir(
            git_dir, root, skip=(data_dir,), deadline=time.monotonic() + WALK_SECONDS
        )
        try:
            unchanged = real == git_dir and git_dir.resolve() == git_dir
        except (OSError, RuntimeError):
            unchanged = False
        if not unchanged:
            left.append(LeftFolder(str(folder), LeftReason.NOT_CONTAINED))
            continue
        folder_real = folder.resolve()
        if _holds(folder_real, guarded):
            left.append(LeftFolder(str(folder), LeftReason.HOLDS_DATA_OR_KEY))
            continue
        identity = _identity(root)
        removals.append(Removal(root, folder_rel, not folder_rel, repo_id, base, identity))
        if folder_rel:
            wanted.extend(_known_inside(session, root_row.id, folder_rel))
        else:
            wanted.extend(
                session.scalars(select(Repository.id).where(Repository.scan_root_id == root_row.id))
            )
        if not spelled_within(git_dir, folder_real):
            rel = _rel(git_dir, root)
            if (
                rel
                and _separate_git_dir_allowed(git_dir, folder_real, root)
                and not _holds(git_dir, guarded)
                and not _known_inside(session, root_row.id, rel)
            ):
                removals.append(Removal(root, rel, False, repo_id, base, identity))
            else:
                left.append(LeftFolder(str(git_dir), LeftReason.SEPARATE_GIT_DIR))
        for worktree_id, pointed in _worktrees(git_dir, root):
            rel = _confirmed_worktree(git_dir, worktree_id, pointed, root)
            if (
                rel
                and not _holds(root / os.fsdecode(rel), guarded)
                and not _known_inside(session, root_row.id, rel)
            ):
                removals.append(Removal(root, rel, False, repo_id, base, identity))
            else:
                shown = (
                    str(pointed) if pointed is not None else f"{git_dir}/worktrees/{worktree_id}"
                )
                left.append(LeftFolder(shown, LeftReason.WORKTREE_UNCONFIRMED))
    ids = tuple(sorted(seen))
    return DeletionPlan(
        ids, tuple(outermost(removals)), tuple(left), _counts(session, ids), tuple(sorted(busy))
    )


def folder_of(removal: Removal) -> Path:
    return removal.root / os.fsdecode(removal.rel) if removal.rel else removal.root


def outermost(removals: list[Removal]) -> list[Removal]:
    ordered = sorted(enumerate(removals), key=lambda pair: (len(folder_of(pair[1]).parts), pair[0]))
    kept: dict[Path, tuple[int, Removal]] = {}
    covered: dict[Path, set[int]] = {}
    for position, removal in ordered:
        here = folder_of(removal)
        outer = next((p for p in (here, *here.parents) if p in kept), None)
        if outer is None:
            kept[here] = (position, removal)
            covered[here] = set()
        elif removal.repository_id != kept[outer][1].repository_id:
            covered[outer].add(removal.repository_id)
    return [
        replace(removal, covers=tuple(sorted(covered[here])))
        for here, (_, removal) in sorted(kept.items(), key=lambda item: item[1][0])
    ]
