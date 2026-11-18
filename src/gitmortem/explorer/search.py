import time
from collections import deque
from collections.abc import Iterator, Sequence, Set
from dataclasses import dataclass, field
from pathlib import Path

from gitmortem.explorer.access import Unavailable, git_read, is_commit, unavailable_for
from gitmortem.explorer.trees import (
    MAX_EXPLORE_BYTES,
    EntryKind,
    PathSegments,
    Record,
    check_segments,
    each_record,
)
from gitmortem.gitread import BINARY_PROBE_BYTES
from gitmortem.gitrun import GitError, GitRunner, GitTimeout
from gitmortem.triage.context import (
    MAX_LINE_CHARS,
    batch_cap,
    clean_line,
    tree_at,
)

__all__ = [
    "BATCH_BYTES",
    "MAX_FILE_HITS",
    "MAX_LINE_HITS",
    "MAX_LISTED_ENTRIES",
    "MAX_LISTING_BYTES",
    "MAX_NAME_HITS",
    "MAX_QUERY_CHARS",
    "MAX_SEARCH_BLOB",
    "MAX_SEARCH_READ",
    "SEARCH_MARGIN_SECONDS",
    "SEARCH_SECONDS",
    "BadQuery",
    "LineHit",
    "NameHit",
    "SearchResult",
    "find_content",
    "find_names",
]

MAX_LISTED_ENTRIES = 1_000_000
MAX_NAME_HITS = 500
MAX_LISTING_BYTES = 64 << 20
MAX_SEARCH_BLOB = MAX_EXPLORE_BYTES
BATCH_BYTES = 16 << 20
MAX_SEARCH_READ = 1 << 30
WINDOW_BYTES = 4 * (MAX_LINE_CHARS + 2)
MAX_LINE_HITS = 1_000
MAX_FILE_HITS = 200
SEARCH_SECONDS = 20
SEARCH_MARGIN_SECONDS = 2
MAX_QUERY_CHARS = 1_000


class BadQuery(ValueError):
    def __init__(self) -> None:
        super().__init__(f"a query is 1 to {MAX_QUERY_CHARS} characters, with no line break or NUL")


@dataclass(frozen=True)
class NameHit:
    path: PathSegments = field(repr=False)
    kind: EntryKind


@dataclass(frozen=True)
class LineHit:
    path: PathSegments = field(repr=False)
    number: int
    text: str = field(repr=False)
    start: int
    end: int
    cut: bool


@dataclass(frozen=True)
class SearchResult:
    hits: tuple[LineHit, ...]
    files: int
    skipped_large: int
    skipped_binary: int
    cut: bool


def _check_query(query: str) -> None:
    if not 0 < len(query) <= MAX_QUERY_CHARS or any(c in query for c in "\n\r\0"):
        raise BadQuery


def _check_path(name: bytes, listed: Set[bytes]) -> None:
    if name.startswith(b"/") or name.endswith(b"/") or b"//" in name:
        raise GitError("ls-tree", 0, "git ls-tree listed a path with an empty segment")
    if name in listed:
        raise GitError("ls-tree", 0, "git ls-tree listed a path twice")


def _checked(records: Iterator[Record], listed: set[bytes]) -> Iterator[Record]:
    for record in records:
        _check_path(record[0], listed)
        listed.add(record[0])
        yield record


def _listed(runner: GitRunner, git_dir: Path, tree: str, how: str, deadline: float) -> bytes:
    return git_read(
        runner,
        git_dir,
        ["ls-tree", "-r", "-z", how, "--full-tree", "--end-of-options", tree],
        deadline,
        max_stdout=MAX_LISTING_BYTES,
    )


def _named(listing: bytes, query: str) -> tuple[tuple[NameHit, ...], bool]:
    hits: list[NameHit] = []
    cut = False
    records = _checked(each_record(listing, sizes=False), set())
    for looked, (name, kind, _, _) in enumerate(records, start=1):
        if cut or looked > MAX_LISTED_ENTRIES:
            cut = True
        elif query in name.rpartition(b"/")[2].decode("utf-8", "replace"):
            if len(hits) == MAX_NAME_HITS:
                cut = True
            else:
                hits.append(NameHit(tuple(name.split(b"/")), kind))
    return tuple(hits), cut


def find_names(
    runner: GitRunner, git_dir: Path, commit: str, query: str, *, deadline: float
) -> tuple[tuple[NameHit, ...], bool] | Unavailable:
    _check_query(query)
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        return _named(_listed(runner, git_dir, commit, "-t", deadline), query)
    except GitError as error:
        return unavailable_for(error)


def _readable(record: Record) -> bool:
    _, kind, size, _ = record
    return kind == "blob" and size is not None and size <= MAX_SEARCH_BLOB


def _printed(record: Record) -> int:
    return batch_cap(record[2] or 0)


def _batch(
    first: Record, rest: Iterator[Record], room: int, left: int
) -> tuple[list[Record], list[int], Record | None]:
    wanted: list[Record] = []
    passed = [0]
    carried = 0
    record: Record | None = first
    while record is not None:
        if _readable(record):
            weight = _printed(record)
            if carried + weight > room:
                if wanted or weight > left:
                    break
                wanted.append(record)
                passed.append(0)
                return wanted, passed, next(rest, None)
            carried += weight
            wanted.append(record)
            passed.append(0)
        elif record[1] == "blob" and record[2] is not None:
            passed[-1] += 1
        record = next(rest, None)
    return wanted, passed, record


_Span = tuple[int, int]


def _read_blobs(
    runner: GitRunner, git_dir: Path, wanted: Sequence[Record], deadline: float
) -> tuple[bytes, list[_Span]]:
    out = git_read(
        runner,
        git_dir,
        ["cat-file", "--batch"],
        deadline,
        stdin=b"".join(object_id + b"\n" for _, _, _, object_id in wanted),
        max_stdout=sum(batch_cap(size or 0) for _, _, size, _ in wanted),
    )
    spans = []
    at = 0
    for _, _, size, object_id in wanted:
        header = b"%s blob %d\n" % (object_id, size or 0)
        start = at + len(header)
        stop = start + (size or 0)
        if out[at:start] != header or out[stop : stop + 1] != b"\n":
            raise GitError("cat-file", 0, "git cat-file did not give the blobs asked for")
        spans.append((start, stop))
        at = stop + 1
    if at != len(out):
        raise GitError("cat-file", 0, "git cat-file gave more than the blobs asked for")
    return out, spans


def _shown(text: str, begin: int, end: int, at: int, size: int) -> tuple[str, int, bool]:
    first = begin
    cut = end - begin > MAX_LINE_CHARS
    if cut:
        lead = (MAX_LINE_CHARS - size) // 2
        first = begin + min(max(at - begin - lead, 0), end - begin - MAX_LINE_CHARS)
    return clean_line(text[first : min(end, first + MAX_LINE_CHARS)]), at - first, cut


_Found = tuple[int, str, int, int, bool]


def _line_hits(data: bytes, span: _Span, query: str, needle: bytes, most: int) -> list[_Found]:
    begin_at, end_at = span
    found: list[_Found] = []
    number, counted = 1, begin_at
    at = data.find(needle, begin_at, end_at)
    while at != -1 and len(found) < most:
        number += data.count(b"\n", counted, at)
        counted = at
        before = data.rfind(b"\n", begin_at, at)
        begin = begin_at if before == -1 else before + 1
        stop = data.find(b"\n", at, end_at)
        stop = end_at if stop == -1 else stop
        close = stop - 1 if stop > begin and data[stop - 1] == ord("\r") else stop
        first = max(begin, at - WINDOW_BYTES)
        last = min(close, at + len(needle) + WINDOW_BYTES)
        text = data[first:last].decode("utf-8", "replace")
        hit = len(data[first:at].decode("utf-8", "replace"))
        shown, start, cut = _shown(text, 0, len(text), hit, len(query))
        found.append((number, shown, start, start + len(query), cut))
        at = data.find(needle, stop, end_at)
    return found


@dataclass
class _Tally:
    hits: list[LineHit] = field(default_factory=list)
    files: int = 0
    large: int = 0
    binary: int = 0

    def result(self, *, cut: bool) -> SearchResult:
        return SearchResult(tuple(self.hits), self.files, self.large, self.binary, cut)

    def take(self, path: PathSegments, data: bytes, span: _Span, query: str, needle: bytes) -> bool:
        found = _line_hits(data, span, query, needle, MAX_LINE_HITS - len(self.hits) + 1)
        if not found:
            return True
        if self.files == MAX_FILE_HITS or len(self.hits) == MAX_LINE_HITS:
            return False
        kept = found[: MAX_LINE_HITS - len(self.hits)]
        for number, shown, start, end, cut in kept:
            self.hits.append(LineHit(path, number, shown, start, end, cut))
        self.files += 1
        return len(kept) == len(found)


def _search(
    runner: GitRunner,
    git_dir: Path,
    folder: PathSegments,
    records: Iterator[Record],
    query: str,
    *,
    until: float,
    deadline: float,
) -> SearchResult:
    tally = _Tally()
    printed = reads = 0
    needle = _needle(query)
    pending = next(records, None)
    while pending is not None:
        left = MAX_SEARCH_READ - printed
        wanted, passed, pending = _batch(pending, records, min(BATCH_BYTES, left), left)
        if not wanted:
            tally.large += passed[0]
            return tally.result(cut=pending is not None)
        if reads and time.monotonic() >= until:
            tally.large += sum(passed)
            return tally.result(cut=True)
        try:
            out, spans = _read_blobs(runner, git_dir, wanted, deadline)
        except GitTimeout:
            if not reads:
                raise
            tally.large += sum(passed)
            return tally.result(cut=True)
        reads += 1
        printed += sum(_printed(record) for record in wanted)
        for (name, _, _, _), span, large in zip(wanted, spans, passed, strict=False):
            tally.large += large
            start, stop = span
            if out.find(b"\0", start, min(stop, start + BINARY_PROBE_BYTES)) != -1:
                tally.binary += 1
            elif needle is not None and not tally.take(
                (*folder, *name.split(b"/")), out, span, query, needle
            ):
                return tally.result(cut=True)
        del out
        tally.large += passed[-1]
    return tally.result(cut=False)


def _needle(query: str) -> bytes | None:
    try:
        return query.encode("utf-8")
    except UnicodeEncodeError:
        return None


def _scan(
    runner: GitRunner,
    git_dir: Path,
    folder: PathSegments,
    listing: bytes,
    query: str,
    *,
    until: float,
    deadline: float,
) -> SearchResult:
    records = _checked(each_record(listing, sizes=True), set())
    found = _search(runner, git_dir, folder, records, query, until=until, deadline=deadline)
    deque(records, maxlen=0)
    return found


def find_content(
    runner: GitRunner,
    git_dir: Path,
    commit: str,
    query: str,
    *,
    folder: PathSegments = (),
    deadline: float,
) -> SearchResult | Unavailable:
    _check_query(query)
    check_segments(folder)
    until = min(time.monotonic() + SEARCH_SECONDS, deadline - SEARCH_MARGIN_SECONDS)
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        tree = tree_at(runner, git_dir, commit, folder, deadline)
        if tree is None:
            return Unavailable.NOT_IN_HISTORY
        listing = _listed(runner, git_dir, tree.decode("ascii"), "-l", deadline)
        return _scan(runner, git_dir, folder, listing, query, until=until, deadline=deadline)
    except GitError as error:
        return unavailable_for(error)
