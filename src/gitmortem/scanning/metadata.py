import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from gitmortem.explorer.commits import MAX_COMMIT_BYTES, MalformedCommit, parse_commit
from gitmortem.gitrun import GitRunner
from gitmortem.scanning.objects import object_batches
from gitmortem.scanning.tools import MESSAGE_LIMIT, bounded

__all__ = ["CommitMeta", "read_commit_meta"]


@dataclass(frozen=True)
class CommitMeta:
    author_name: str
    author_email: str
    authored_at: datetime | None
    message: str = field(repr=False)
    message_cut: bool


def _meta(raw: bytes, oid: str) -> CommitMeta | None:
    try:
        commit = parse_commit(raw)
    except MalformedCommit:
        return None
    if commit.id != oid:
        return None
    at = commit.author.at
    message = commit.message
    return CommitMeta(
        author_name=bounded(commit.author.name),
        author_email=bounded(commit.author.email),
        authored_at=None if at is None else at.astimezone(UTC),
        message=bounded(message, MESSAGE_LIMIT),
        message_cut=len(message.encode("utf-8", "replace")) > MESSAGE_LIMIT,
    )


def read_commit_meta(
    runner: GitRunner,
    git_dir: Path,
    commits: Sequence[str],
    *,
    timeout: float,
    cancel: threading.Event | None = None,
) -> dict[str, CommitMeta]:
    found: dict[str, CommitMeta] = {}
    for oid, raw in object_batches(
        runner,
        git_dir,
        commits,
        kind="commit",
        max_size=MAX_COMMIT_BYTES,
        timeout=timeout,
        cancel=cancel,
    ):
        meta = _meta(raw, oid)
        if meta is not None:
            found[oid] = meta
    return found
