import heapq
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from gitmortem.explorer.access import Unavailable, is_commit, unavailable_for
from gitmortem.gitread import BINARY_PROBE_BYTES, OBJECT_ID
from gitmortem.gitrun import GitError, GitRunner
from gitmortem.triage.context import (
    blob_at,
    blob_bytes,
    blob_size,
    clean_file_text,
    tree_at,
    tree_listing,
)

__all__ = [
    "MAX_EXPLORE_BYTES",
    "MAX_FOLDER_ENTRIES",
    "MAX_PATH_BYTES",
    "MAX_SEGMENT_BYTES",
    "BadPath",
    "Entry",
    "EntryKind",
    "FileContent",
    "Folder",
    "PathSegments",
    "Record",
    "check_segments",
    "each_record",
    "list_folder",
    "read_file",
]

MAX_FOLDER_ENTRIES = 5_000
MAX_SEGMENT_BYTES = 4_096
MAX_EXPLORE_BYTES = 250 << 20
MAX_PATH_BYTES = 65_536

PathSegments = tuple[bytes, ...]
EntryKind = Literal["blob", "tree", "link", "submodule"]
Record = tuple[bytes, EntryKind, int | None, bytes]

_LINK_MODE = b"120000"
_NO_SIZE = b"BAD"


class BadPath(ValueError):
    def __init__(self) -> None:
        super().__init__(
            f"each segment of a path is 1 to {MAX_SEGMENT_BYTES} bytes,"
            f" and all of them together at most {MAX_PATH_BYTES}"
        )


@dataclass(frozen=True)
class Entry:
    name: bytes = field(repr=False)
    kind: EntryKind
    size: int | None
    object_id: str


@dataclass(frozen=True)
class Folder:
    entries: tuple[Entry, ...]
    total: int
    truncated: bool


@dataclass(frozen=True)
class FileContent:
    text: str | None = field(repr=False)
    binary: bool
    size: int
    too_large: bool


def check_segments(path: PathSegments) -> None:
    if not all(0 < len(segment) <= MAX_SEGMENT_BYTES for segment in path):
        raise BadPath
    if sum(len(segment) for segment in path) > MAX_PATH_BYTES:
        raise BadPath


def _record(record: bytes, fields: int) -> Record:
    meta, tab, name = record.partition(b"\t")
    parts = meta.split()
    if not tab or not name or len(parts) != fields or OBJECT_ID.fullmatch(parts[2]) is None:
        raise GitError("ls-tree", 0, "git ls-tree printed an entry it should not")
    mode, kind, object_id = parts[:3]
    size = parts[3] if fields == 4 else None
    if kind == b"blob" and (size is None or size.isdigit() or size == _NO_SIZE):
        shown = int(size) if size is not None and size.isdigit() else None
        return name, "link" if mode == _LINK_MODE else "blob", shown, object_id
    if kind in (b"tree", b"commit") and size in (None, b"-"):
        return name, "tree" if kind == b"tree" else "submodule", None, object_id
    raise GitError("ls-tree", 0, "git ls-tree printed an entry it should not")


def _ended(listing: bytes) -> None:
    if listing and not listing.endswith(b"\0"):
        raise GitError("ls-tree", 0, "git ls-tree did not end its listing")


def each_record(listing: bytes, *, sizes: bool) -> Iterator[Record]:
    _ended(listing)
    fields = 4 if sizes else 3
    at = 0
    while at < len(listing):
        stop = listing.index(b"\0", at)
        yield _record(listing[at:stop], fields)
        at = stop + 1


def _shown_first(record: Record) -> tuple[bool, bytes]:
    return record[1] != "tree", record[0]


def _first_entries(listing: bytes) -> tuple[list[Record], int]:
    total = 0

    def counted() -> Iterator[Record]:
        nonlocal total
        for record in each_record(listing, sizes=True):
            total += 1
            yield record

    kept = heapq.nsmallest(MAX_FOLDER_ENTRIES, counted(), key=_shown_first)
    return kept, total


def list_folder(
    runner: GitRunner, git_dir: Path, commit: str, path: PathSegments, *, deadline: float
) -> Folder | Unavailable:
    check_segments(path)
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        tree = tree_at(runner, git_dir, commit, path, deadline)
        if tree is None:
            return Unavailable.NOT_IN_HISTORY
        kept, total = _first_entries(tree_listing(runner, git_dir, tree, deadline, long=True))
    except GitError as error:
        return unavailable_for(error)
    return Folder(
        entries=tuple(Entry(name, kind, size, oid.decode()) for name, kind, size, oid in kept),
        total=total,
        truncated=total > MAX_FOLDER_ENTRIES,
    )


def read_file(
    runner: GitRunner, git_dir: Path, commit: str, path: PathSegments, *, deadline: float
) -> FileContent | Unavailable:
    check_segments(path)
    if not path:
        return Unavailable.NOT_IN_HISTORY
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        blob = blob_at(runner, git_dir, commit, path, deadline)
        if blob is None:
            return Unavailable.NOT_IN_HISTORY
        size = blob_size(runner, git_dir, blob, deadline)
        if size is None:
            return Unavailable.UNREADABLE
        if size > MAX_EXPLORE_BYTES:
            return FileContent(text=None, binary=False, size=size, too_large=True)
        data = blob_bytes(runner, git_dir, blob, deadline, most=MAX_EXPLORE_BYTES)
    except GitError as error:
        return unavailable_for(error)
    if isinstance(data, Unavailable):
        return data
    if b"\0" in data[:BINARY_PROBE_BYTES]:
        return FileContent(text=None, binary=True, size=len(data), too_large=False)
    return FileContent(
        text=clean_file_text(data.decode("utf-8", "replace")),
        binary=False,
        size=len(data),
        too_large=False,
    )
