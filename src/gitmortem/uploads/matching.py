import os
import threading
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.db.models import Repository, RepositoryKind, RepositoryVersion
from gitmortem.gitrun import GitCancelled, GitError, GitRunner, GitTimeout, repo_tips
from gitmortem.trees import remove_tree
from gitmortem.uploads.found import FoundRepo
from gitmortem.uploads.rebuild import Rebuilt

MAX_LISTING = 256 << 20


@dataclass(frozen=True)
class New:
    pass


@dataclass(frozen=True)
class Update:
    repository_id: int
    keep_old: bool


@dataclass(frozen=True)
class Takeover:
    repository_id: int


@dataclass(frozen=True)
class Ask:
    candidate_ids: tuple[int, ...]


Decision = New | Update | Takeover | Ask


@dataclass(frozen=True)
class Candidate:
    repository_id: int
    org: str | None
    versions: tuple[Path, ...]


def candidates(session: Session, name: str) -> list[Candidate]:
    found = []
    for repo in session.scalars(
        select(Repository)
        .where(
            Repository.kind == RepositoryKind.UPLOADED,
            Repository.name == name,
            Repository.deletion_state.is_(None),
        )
        .order_by(Repository.id)
    ):
        versions = tuple(
            Path(os.fsdecode(git_dir))
            for git_dir in session.scalars(
                select(RepositoryVersion.git_dir)
                .where(
                    RepositoryVersion.repository_id == repo.id,
                    RepositoryVersion.removed_at.is_(None),
                )
                .order_by(RepositoryVersion.current.desc(), RepositoryVersion.id.desc())
            )
        )
        if versions:
            found.append(Candidate(repo.id, repo.org, versions))
    return found


def _left(deadline: float) -> float:
    return max(1.0, deadline - time.monotonic())


def _commits(
    runner: GitRunner, git_dir: Path, deadline: float, cancel: threading.Event | None
) -> bytes:
    return runner.run(
        ["rev-list", "--all", "--reflog"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(git_dir)},
        timeout=_left(deadline),
        cancel=cancel,
        max_stdout=MAX_LISTING,
    )


def shares_history(
    runner: GitRunner,
    new_git_dir: Path,
    versions: Sequence[Path],
    *,
    deadline: float,
    cancel: threading.Event | None = None,
) -> bool:
    ids = _commits(runner, new_git_dir, deadline, cancel)
    if not ids.strip():
        return False
    for version in versions:
        found = runner.run(
            ["cat-file", "--batch-check=%(objecttype)"],
            cwd=runner.private_dir,
            stdin=ids,
            extra_env={"GIT_DIR": str(version)},
            timeout=_left(deadline),
            cancel=cancel,
            max_stdout=MAX_LISTING,
        )
        if any(line == b"commit" for line in found.splitlines()):
            return True
    return False


def lacks_anything(
    runner: GitRunner,
    current: Path,
    new_git_dir: Path,
    *,
    scratch: Path,
    deadline: float,
    cancel: threading.Event | None = None,
) -> bool:
    old_tips = repo_tips(runner, current, timeout=_left(deadline), cancel=cancel)
    new_tips = repo_tips(runner, new_git_dir, timeout=_left(deadline), cancel=cancel)
    if not old_tips:
        return False
    scratch.mkdir(mode=0o700, parents=True)
    try:
        runner.run(
            ["init", "--bare", "-q", "--template="],
            cwd=runner.private_dir,
            extra_env={"GIT_DIR": str(scratch)},
            timeout=_left(deadline),
        )
        alternates = scratch / "objects" / "info" / "alternates"
        alternates.write_bytes(
            b"".join(
                os.fsencode(source.resolve() / "objects") + b"\n"
                for source in (current, new_git_dir)
            )
        )
        revs = b"".join(tip + b"\n" for tip in old_tips) + b"--not\n"
        revs += b"".join(tip + b"\n" for tip in new_tips)
        counted = runner.run(
            ["rev-list", "--count", "--stdin"],
            cwd=runner.private_dir,
            stdin=revs,
            extra_env={"GIT_DIR": str(scratch)},
            timeout=_left(deadline),
            cancel=cancel,
        )
        if int(counted) > 0:
            return True
        return _missing_objects(runner, current, new_git_dir, old_tips, deadline, cancel)
    finally:
        remove_tree(scratch, ignore_errors=True)


def _missing_objects(
    runner: GitRunner,
    current: Path,
    new_git_dir: Path,
    old_tips: Sequence[bytes],
    deadline: float,
    cancel: threading.Event | None,
) -> bool:
    try:
        listed = runner.run(
            ["rev-list", "--objects", "--stdin"],
            cwd=runner.private_dir,
            stdin=b"".join(tip + b"\n" for tip in old_tips),
            extra_env={"GIT_DIR": str(current)},
            timeout=_left(deadline),
            cancel=cancel,
            max_stdout=MAX_LISTING,
        )
        oids = b"".join(line.split(b" ", 1)[0] + b"\n" for line in listed.splitlines() if line)
        found = runner.run(
            ["cat-file", "--batch-check=%(objectname)"],
            cwd=runner.private_dir,
            stdin=oids,
            extra_env={"GIT_DIR": str(new_git_dir)},
            timeout=_left(deadline),
            cancel=cancel,
            max_stdout=MAX_LISTING,
        )
    except (GitCancelled, GitTimeout):
        raise
    except GitError:
        return True
    return any(line.endswith(b" missing") for line in found.splitlines())


@dataclass(frozen=True)
class Known:
    candidates: tuple[Candidate, ...]
    named_by_import: int | None


def known_for(session: Session, found: FoundRepo) -> Known:
    named_by_import = None
    if found.org is not None:
        named_by_import = session.scalars(
            select(Repository.id).where(
                Repository.kind == RepositoryKind.NOT_ON_DISK,
                Repository.org == found.org,
                Repository.name == found.name,
                Repository.deletion_state.is_(None),
            )
        ).one_or_none()
    return Known(tuple(candidates(session, found.name)), named_by_import)


def decide(
    runner: GitRunner,
    found: FoundRepo,
    rebuilt: Rebuilt,
    known: Known,
    *,
    scratch: Path,
    deadline: float,
    cancel: threading.Event | None = None,
) -> Decision:
    sharing = [
        c
        for c in known.candidates
        if shares_history(runner, rebuilt.git_dir, c.versions, deadline=deadline, cancel=cancel)
    ]
    if len(sharing) == 1:
        chosen = sharing[0]
        keep = rebuilt.dropped_objects > 0 or lacks_anything(
            runner,
            chosen.versions[0],
            rebuilt.git_dir,
            scratch=scratch,
            deadline=deadline,
            cancel=cancel,
        )
        return Update(chosen.repository_id, keep_old=keep)
    if sharing:
        return Ask(tuple(c.repository_id for c in sharing))
    same_place = [c.repository_id for c in known.candidates if c.org == found.org]
    if same_place:
        return Ask(tuple(same_place))
    if known.named_by_import is not None:
        return Takeover(known.named_by_import)
    return New()


def resolve_conflicts(decisions: Sequence[Decision]) -> list[Decision]:
    targets = Counter(d.repository_id for d in decisions if isinstance(d, Update | Takeover))
    return [
        Ask((d.repository_id,))
        if isinstance(d, Update | Takeover) and targets[d.repository_id] > 1
        else d
        for d in decisions
    ]
