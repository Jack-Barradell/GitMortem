import itertools
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import re2

from gitmortem.db.models import FindingPlace
from gitmortem.gitread import (
    BINARY_PROBE_BYTES,
    FULL_HEX,
    MATCH_LIMIT,
    MAX_VIEW_BYTES,
    OBJECT_ID,
    git_env,
)
from gitmortem.gitrun import GitError, GitOutputTooLarge, GitRunner
from gitmortem.scanning.blob_cache import BlobCache
from gitmortem.scanning.objects import object_batches
from gitmortem.scanning.repos import display_path
from gitmortem.scanning.tools import bounded_bytes

__all__ = [
    "MAX_CHANGE_LISTING",
    "FindingPlace",
    "ReportedPlace",
    "ResolvedPlace",
    "resolve_places",
]

MAX_CHANGE_LISTING = 64 << 20
_BLOB_MODES = (b"100644", b"100755", b"120000")
_UNDECODED = re.compile("[\udc80-\udcff]+")
_CHANGE = re.compile(rb":[0-7]{6} ([0-7]{6}) [0-9a-f]{40} ([0-9a-f]{40}) [A-Z][0-9]*")

_DIFF_TREE = (
    "diff-tree",
    "--stdin",
    "-r",
    "-z",
    "--no-renames",
    "--root",
    "--diff-merges=first-parent",
)

Shape = tuple[str, ...]


@dataclass(frozen=True)
class ReportedPlace:
    commit: str
    reported_path: str | None
    line: int
    holding: bytes | None = field(default=None, repr=False)
    exact_path: bytes | None = None


@dataclass(frozen=True)
class ResolvedPlace:
    place: FindingPlace
    path: bytes
    display_path: str
    line: int
    matched_line: bytes | None = field(repr=False)


def _shape(text: str, replacement: str) -> Shape:
    return tuple(re.split(f"(?:{re.escape(replacement)})+", text))


def _path_shape(raw: bytes, replacement: str) -> Shape:
    text = raw.decode("utf-8", "surrogateescape")
    return _shape(_UNDECODED.sub(replacement, text), replacement)


Wanted = Shape | bytes


def _changes(
    out: bytes, wanted: Mapping[str, set[Wanted]], replacement: str
) -> dict[str, dict[Wanted, list[tuple[bytes, str]]]]:
    found: dict[str, dict[Wanted, list[tuple[bytes, str]]]] = {}
    commit: str | None = None
    at = 0
    while at < len(out):
        end = out.find(b"\0", at)
        if end == -1:
            raise GitError("diff-tree", 0, "git diff-tree did not end its listing")
        record = out[at:end]
        if OBJECT_ID.fullmatch(record):
            commit = record.decode("ascii")
            at = end + 1
            continue
        change = _CHANGE.fullmatch(record)
        path_end = out.find(b"\0", end + 1)
        if change is None or commit is None or path_end == -1:
            raise GitError("diff-tree", 0, "git diff-tree printed what is no change")
        path = out[end + 1 : path_end]
        at = path_end + 1
        if change[1] not in _BLOB_MODES:
            continue
        names = wanted.get(commit, set())
        for key in (path, _path_shape(path, replacement)):
            if key in names:
                found.setdefault(commit, {}).setdefault(key, []).append(
                    (path, change[2].decode("ascii"))
                )
    return found


def _list_changes(
    runner: GitRunner,
    git_dir: Path,
    wanted: Mapping[str, set[Wanted]],
    replacement: str,
    *,
    timeout: float,
    cancel: threading.Event | None,
) -> dict[str, dict[Wanted, list[tuple[bytes, str]]]]:
    def listing(commits: Sequence[str]) -> dict[str, dict[Wanted, list[tuple[bytes, str]]]]:
        out = runner.run(
            list(_DIFF_TREE),
            cwd=runner.private_dir,
            stdin="".join(f"{commit}\n" for commit in commits).encode("ascii"),
            timeout=timeout,
            cancel=cancel,
            extra_env=git_env(git_dir),
            max_stdout=MAX_CHANGE_LISTING,
        )
        return _changes(out, wanted, replacement)

    commits = list(wanted)
    try:
        return listing(commits)
    except GitOutputTooLarge:
        if len(commits) == 1:
            return {}
    found: dict[str, dict[Wanted, list[tuple[bytes, str]]]] = {}
    for commit in commits:
        try:
            found.update(listing([commit]))
        except GitOutputTooLarge:
            continue
    return found


def _lines(blob: bytes, numbers: set[int]) -> dict[int, bytes]:
    found: dict[int, bytes] = {}
    if not numbers:
        return found
    last = max(numbers)
    start, number = 0, 1
    while number <= last and start < len(blob):
        end = blob.find(b"\n", start)
        stop = len(blob) if end == -1 else end
        if number in numbers:
            found[number] = bounded_bytes(blob[start:stop], MATCH_LIMIT)
        if end == -1:
            break
        start, number = end + 1, number + 1
    return found


Search = tuple[int, bytes]
NEAR_BYTES = 4 * MATCH_LIMIT
PARTS_MAX_MEM = 64 << 20


def _line_starts(blob: bytes, wanted: set[int]) -> dict[int, int]:
    starts: dict[int, int] = {}
    last = max(wanted)
    line, offset = 1, 0
    while True:
        if line in wanted:
            starts[line] = offset
        if line >= last:
            return starts
        end = blob.find(b"\n", offset)
        if end == -1:
            return starts
        line, offset = line + 1, end + 1


def _held(blob: bytes, searches: set[Search]) -> dict[Search, int]:
    found: dict[Search, int] = {}
    if not searches:
        return found
    starts = _line_starts(blob, {start for start, _ in searches})
    pending: dict[bytes, list[tuple[int, int]]] = {}
    for start, part in sorted(searches):
        if start in starts and part:
            pending.setdefault(part, []).append((starts[start], start))
    if not pending:
        return found
    either = b"|".join(re2.escape(part) for part in sorted(pending, key=len, reverse=True))
    try:
        program = re2._Regexp(either, _options())
    except re2.error:
        return _held_near(blob, pending)
    prefixes = {part: [other for other in pending if part.startswith(other)] for part in pending}
    line, counted = 1, 0
    left = sum(len(waiting) for waiting in pending.values())
    at = min(offset for held in pending.values() for offset, _ in held)
    while left:
        match = program.search(blob, at)
        if match is None:
            break
        at = match.start()
        line += blob.count(b"\n", counted, at)
        counted = at
        for part in prefixes[blob[at : match.end()]]:
            waiting = pending[part]
            while waiting and waiting[0][0] <= at:
                _, start = waiting.pop(0)
                found[(start, part)] = line
                left -= 1
        at += 1
    return found


def _held_near(blob: bytes, pending: Mapping[bytes, list[tuple[int, int]]]) -> dict[Search, int]:
    found: dict[Search, int] = {}
    for part, waiting in pending.items():
        for offset, start in waiting:
            at = blob.find(part, offset, offset + NEAR_BYTES + len(part))
            if at != -1:
                found[(start, part)] = start + blob.count(b"\n", offset, at)
    return found


def _options() -> re2.Options:
    options = re2.Options()
    options.max_mem = PARTS_MAX_MEM
    options.log_errors = False
    return options


@dataclass(frozen=True)
class _Blob:
    lines: dict[int, bytes] = field(repr=False)
    found: dict[Search, int] = field(repr=False)


def _read_blobs(
    runner: GitRunner,
    git_dir: Path,
    wanted: Mapping[str, set[int]],
    searches: Mapping[str, set[Search]],
    *,
    timeout: float,
    cancel: threading.Event | None,
    cache: BlobCache,
) -> dict[str, _Blob | None]:
    read: dict[str, _Blob | None] = {}
    held = {blob: cache.get(blob) for blob in wanted}
    unread = [blob for blob, content in held.items() if content is None]
    fetched = object_batches(
        runner,
        git_dir,
        unread,
        kind="blob",
        max_size=MAX_VIEW_BYTES,
        timeout=timeout,
        cancel=cancel,
    )
    cached = ((blob, content) for blob, content in held.items() if content is not None)
    for blob, content in itertools.chain(cached, fetched):
        cache.put(blob, content)
        if b"\0" in content[:BINARY_PROBE_BYTES]:
            read[blob] = None
            continue
        found = _held(content, searches.get(blob, set()))
        read[blob] = _Blob(_lines(content, wanted[blob] | set(found.values())), found)
    return read


def resolve_places(
    runner: GitRunner,
    git_dir: Path,
    places: Sequence[ReportedPlace],
    *,
    replacement: str,
    timeout: float,
    cancel: threading.Event | None = None,
    cache: BlobCache | None = None,
) -> list[ResolvedPlace]:
    if not replacement:
        raise ValueError("a replacement stands for undecodable bytes, so it cannot be empty")
    wanted: dict[str, set[Wanted]] = {}
    for reported in places:
        if reported.reported_path is not None and FULL_HEX.fullmatch(reported.commit):
            wanted.setdefault(reported.commit, set()).add(_wanted(reported, replacement))
    changes = (
        _list_changes(runner, git_dir, wanted, replacement, timeout=timeout, cancel=cancel)
        if wanted
        else {}
    )
    found: list[tuple[ReportedPlace, tuple[bytes, str] | None]] = []
    lines: dict[str, set[int]] = {}
    searches: dict[str, set[Search]] = {}
    for reported in places:
        exact = None
        if reported.reported_path is not None:
            key = _wanted(reported, replacement)
            candidates = changes.get(reported.commit, {}).get(key, [])
            exact = candidates[0] if len(candidates) == 1 else None
        if exact is not None:
            wanted_lines = lines.setdefault(exact[1], set())
            if reported.line > 0:
                wanted_lines.add(reported.line)
            if reported.holding:
                searches.setdefault(exact[1], set()).add(_search(reported))
        found.append((reported, exact))
    blobs = (
        _read_blobs(
            runner,
            git_dir,
            lines,
            searches,
            timeout=timeout,
            cancel=cancel,
            cache=BlobCache() if cache is None else cache,
        )
        if lines
        else {}
    )
    return [_resolved(reported, exact, blobs) for reported, exact in found]


def _wanted(reported: ReportedPlace, replacement: str) -> Wanted:
    if reported.exact_path is not None:
        return reported.exact_path
    return _shape(reported.reported_path or "", replacement)


def _search(reported: ReportedPlace) -> Search:
    return max(reported.line, 1), reported.holding or b""


def _resolved(
    reported: ReportedPlace,
    exact: tuple[bytes, str] | None,
    blobs: Mapping[str, _Blob | None],
) -> ResolvedPlace:
    line = reported.line
    if reported.reported_path is None:
        return ResolvedPlace(FindingPlace.MESSAGE, b"", "", line, None)
    if exact is None:
        path = reported.exact_path
        if path is None:
            path = reported.reported_path.encode("utf-8", "replace")
        return ResolvedPlace(FindingPlace.UNRESOLVED, path, display_path(path), line, None)
    path, blob = exact
    shown = display_path(path)
    if blob not in blobs:
        place = FindingPlace.LINE if line >= 0 else FindingPlace.UNRESOLVED
        return ResolvedPlace(place, path, shown, line, None)
    read = blobs[blob]
    if read is None:
        return ResolvedPlace(FindingPlace.BINARY, path, shown, line, None)
    if reported.holding:
        line = read.found.get(_search(reported), line)
    if line == 0:
        return ResolvedPlace(FindingPlace.LINE, path, shown, line, None)
    if line not in read.lines:
        return ResolvedPlace(FindingPlace.UNRESOLVED, path, shown, line, None)
    return ResolvedPlace(FindingPlace.LINE, path, shown, line, read.lines[line])
