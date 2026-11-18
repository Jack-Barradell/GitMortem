import os
import re
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.db.models import (
    IntegrityState,
    Repository,
    RepositoryKind,
    RepositoryRefusal,
    RepositoryVersion,
    ScanRoot,
    ToolRun,
)
from gitmortem.gitread import FULL_HEX, git_env
from gitmortem.gitrun import GitError, GitOutputTooLarge, GitRunner, GitTimeout, shadow_problem
from gitmortem.scanning.repos import contained_git_dir
from gitmortem.scanning.roots import root_is_usable
from gitmortem.uploads.place import contained_upload_git_dir, uploads_dir

__all__ = [
    "CONTEXT_WALK_SECONDS",
    "NoSuchRepository",
    "RepoRead",
    "Unavailable",
    "checked_git_dir",
    "git_read",
    "is_commit",
    "open_for_read",
    "unavailable_for",
]

CONTEXT_WALK_SECONDS = 10


_FULL_SHA1 = re.compile(r"[0-9a-f]{40}")


class Unavailable(StrEnum):
    REPOSITORY_GONE = "repository_gone"
    REFUSED = "refused"
    NOT_IN_HISTORY = "not_in_history"
    BINARY = "binary"
    TOO_LARGE = "too_large"
    TIMED_OUT = "timed_out"
    UNREADABLE = "unreadable"
    NOT_ON_DISK = "not_on_disk"


class NoSuchRepository(LookupError):
    def __init__(self, repository_id: int) -> None:
        super().__init__(f"no repository {repository_id}")
        self.repository_id = repository_id


@dataclass(frozen=True)
class RepoRead:
    repository_id: int
    git_dir: Path
    root: Path
    integrity_failed: bool
    uploaded: bool = False
    versions: tuple[Path, ...] = ()


def _integrity_failed(session: Session, repository_id: int) -> bool:
    latest = session.scalar(
        select(ToolRun.integrity)
        .where(
            ToolRun.repository_id == repository_id,
            ToolRun.integrity.in_((IntegrityState.VERIFIED, IntegrityState.FAILED)),
        )
        .order_by(ToolRun.finished_at.desc(), ToolRun.id.desc())
        .limit(1)
    )
    return latest == IntegrityState.FAILED


def open_for_read(
    session: Session, repository_id: int, *, version_id: int | None = None
) -> RepoRead | Unavailable:
    found = session.execute(
        select(
            Repository.kind,
            Repository.git_dir,
            Repository.deletion_state,
            ScanRoot.path,
            ScanRoot.removed_at,
        )
        .outerjoin(ScanRoot, ScanRoot.id == Repository.scan_root_id)
        .where(Repository.id == repository_id)
    ).first()
    if found is None:
        raise NoSuchRepository(repository_id)
    kind, git_dir, deletion, root, removed_at = found
    if deletion is not None:
        return Unavailable.REPOSITORY_GONE
    if kind is RepositoryKind.UPLOADED:
        return _uploaded_read(session, repository_id, version_id)
    if version_id is not None:
        raise NoSuchRepository(repository_id)
    if kind is RepositoryKind.NOT_ON_DISK or git_dir is None or root is None:
        return Unavailable.NOT_ON_DISK
    if removed_at is not None:
        return Unavailable.REPOSITORY_GONE
    return RepoRead(
        repository_id=repository_id,
        git_dir=Path(os.fsdecode(git_dir)),
        root=Path(root),
        integrity_failed=_integrity_failed(session, repository_id),
    )


def _uploaded_read(session: Session, repository_id: int, version_id: int | None) -> RepoRead:
    kept = session.execute(
        select(RepositoryVersion.id, RepositoryVersion.git_dir)
        .where(
            RepositoryVersion.repository_id == repository_id,
            RepositoryVersion.removed_at.is_(None),
        )
        .order_by(RepositoryVersion.current.desc(), RepositoryVersion.id.desc())
    ).all()
    if not kept:
        raise NoSuchRepository(repository_id)
    paths = {row_id: Path(os.fsdecode(git_dir)) for row_id, git_dir in kept}
    if version_id is not None and version_id not in paths:
        raise NoSuchRepository(repository_id)
    chosen = paths[version_id if version_id is not None else kept[0][0]]
    return RepoRead(
        repository_id=repository_id,
        git_dir=chosen,
        root=chosen,
        integrity_failed=_integrity_failed(session, repository_id),
        uploaded=True,
        versions=tuple(paths[row_id] for row_id, _ in kept),
    )


def checked_git_dir(
    runner: GitRunner,
    read: RepoRead,
    *,
    bases: Collection[Path],
    data_dir: Path,
    key_file: Path | None,
    deadline: float,
) -> Path | Unavailable:
    if not os.path.lexists(read.git_dir):
        return Unavailable.REPOSITORY_GONE
    walk_until = time.monotonic() + CONTEXT_WALK_SECONDS
    if read.uploaded:
        real = contained_upload_git_dir(read.git_dir, uploads_dir(data_dir), deadline=walk_until)
    elif not root_is_usable(read.root, bases=bases, data_dir=data_dir, key_file=key_file):
        return Unavailable.REFUSED
    else:
        real = contained_git_dir(read.git_dir, read.root, skip=(data_dir,), deadline=walk_until)
    if isinstance(real, RepositoryRefusal) or real != read.git_dir:
        return Unavailable.REFUSED
    left = deadline - time.monotonic()
    if left <= 0:
        return Unavailable.TIMED_OUT
    try:
        problem = shadow_problem(runner, real, timeout=left)
    except GitTimeout:
        return Unavailable.TIMED_OUT
    except GitError:
        return Unavailable.REFUSED if os.path.lexists(read.git_dir) else Unavailable.REPOSITORY_GONE
    if problem is not None:
        return Unavailable.REFUSED
    return real


def holding_version(
    runner: GitRunner,
    read: RepoRead,
    commit: str,
    *,
    bases: Collection[Path],
    data_dir: Path,
    key_file: Path | None,
    deadline: float,
) -> Path | Unavailable:
    if len(read.versions) < 2 or _FULL_SHA1.fullmatch(commit) is None:
        return checked_git_dir(
            runner, read, bases=bases, data_dir=data_dir, key_file=key_file, deadline=deadline
        )
    for version in read.versions:
        checked = checked_git_dir(
            runner,
            replace(read, git_dir=version),
            bases=bases,
            data_dir=data_dir,
            key_file=key_file,
            deadline=deadline,
        )
        if isinstance(checked, Unavailable):
            return checked
        left = deadline - time.monotonic()
        if left <= 0:
            return Unavailable.TIMED_OUT
        try:
            held = runner.run(
                ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{commit}^{{commit}}"],
                cwd=runner.private_dir,
                extra_env=git_env(checked),
                ok_codes=(0, 1),
                timeout=left,
                max_stdout=4096,
            )
        except GitTimeout:
            return Unavailable.TIMED_OUT
        except GitError:
            return Unavailable.REFUSED
        if held.strip():
            return checked
    return checked_git_dir(
        runner, read, bases=bases, data_dir=data_dir, key_file=key_file, deadline=deadline
    )


def git_read(
    runner: GitRunner,
    git_dir: Path,
    args: Sequence[str],
    deadline: float,
    *,
    stdin: bytes | None = None,
    ok_codes: Collection[int] = (0,),
    max_stdout: int | None = None,
) -> bytes:
    left = deadline - time.monotonic()
    if left <= 0:
        raise GitTimeout(args[0], 0)
    return runner.run(
        args,
        cwd=runner.private_dir,
        stdin=stdin,
        timeout=left,
        ok_codes=ok_codes,
        extra_env=git_env(git_dir),
        max_stdout=max_stdout,
    )


def is_commit(runner: GitRunner, git_dir: Path, commit: str, *, deadline: float) -> bool:
    if FULL_HEX.fullmatch(commit) is None:
        return False
    verified = git_read(
        runner,
        git_dir,
        ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{commit}^{{commit}}"],
        deadline,
        ok_codes=(0, 1),
    )
    return verified.strip() == commit.encode("ascii")


def unavailable_for(error: GitError) -> Unavailable:
    if isinstance(error, GitTimeout):
        return Unavailable.TIMED_OUT
    if isinstance(error, GitOutputTooLarge):
        return Unavailable.TOO_LARGE
    return Unavailable.UNREADABLE
