import base64
import codecs
import contextlib
import hashlib
import json
import os
import re
import sys
import threading
import time
from array import array
from collections import Counter, deque
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum, auto
from pathlib import Path
from typing import Any

import re2

from gitmortem.gitread import (
    BINARY_PROBE_BYTES,
    MATCH_LIMIT,
    MAX_VIEW_BYTES,
    OBJECT_ID,
    git_env,
    unquote_c_style,
)
from gitmortem.gitrun import GitCancelled, GitError, GitRunner, GitTimeout
from gitmortem.scanning.objects import object_batches
from gitmortem.scanning.rule_patterns import (
    VALUE_GROUP,
    CompiledRule,
    RuleRefusal,
    StoredRule,
    compile_rule,
    run_budget,
    scan_options,
)

__all__ = [
    "CHILD_BAD_RULES",
    "CHILD_TIMED_OUT",
    "CHILD_UNREADABLE",
    "CHILD_WALKED",
    "HEADER_LIMIT",
    "LINES_A_CALL",
    "MAX_DIFFED_FILE_BYTES",
    "MAX_MERGE_HELD_BYTES",
    "REPLACEMENT",
    "REREAD_BATCH",
    "REREAD_BYTES",
    "AddedLine",
    "Gap",
    "Matches",
    "RuleSet",
    "Span",
    "added_lines",
    "compile_rule_set",
    "gap_counts",
    "go_text",
    "write_hits_file",
]

REPLACEMENT = "\ufffd"

_REV_LIST = ("rev-list", "--all", "--parents")
_DIFF_TREE = (
    "diff-tree",
    "--stdin",
    "--always",
    "-r",
    "-p",
    "-U0",
    "--full-index",
    "--no-renames",
    "--no-textconv",
    "--no-ext-diff",
    "--root",
)
MAX_DIFFED_FILE_BYTES = 250 << 20
LINES_A_CALL = 1_000
REREAD_BATCH = 512
REREAD_BYTES = 1 << 20
MAX_MERGE_HELD_BYTES = 64 << 20
HEADER_LIMIT = 1 << 20
_LINE_HOLD = MATCH_LIMIT + 1
_LONG_HEAD = 64
_NULL_ID = b"0" * 40
_GITLINK = b"160000"
_HUNK = re.compile(rb"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_INDEX = re.compile(rb"index ([0-9a-f]{40})\.\.([0-9a-f]{40})(?: ([0-7]{6}))?")
_MODE = re.compile(rb"(old mode|new mode|deleted file mode|new file mode) ([0-7]{6})")
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
_GO = "gitmortem-go"
CHILD_WALKED = 0
CHILD_TIMED_OUT = 3
CHILD_UNREADABLE = 4
CHILD_BAD_RULES = 5


def _one_per_byte(error: UnicodeError) -> tuple[str, int]:
    if not isinstance(error, UnicodeDecodeError):
        raise error
    return REPLACEMENT, error.start + 1


codecs.register_error(_GO, _one_per_byte)


def go_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", _GO)


class Gap(StrEnum):
    BINARY = "binary"
    TOO_LARGE = "too_large"
    LONG_LINES = "long_lines"
    UNREADABLE = "unreadable"
    MERGES_OVER_REPORTED = "merges_over_reported"
    PATHS_OVER_REPORTED = "paths_over_reported"
    DUPLICATE_PATHS = "duplicate_paths"


Span = tuple[int, int, int, int]
Matches = tuple[tuple[StoredRule, tuple[Span, ...]], ...]


@dataclass(frozen=True)
class _Filter:
    set: Any = field(repr=False)
    members: tuple[int, ...]

    def candidates(self, text: str) -> Iterable[int]:
        found = self.set.Match(text)
        sentinel = len(self.members)
        if found is None or sentinel not in found:
            return self.members
        return [self.members[index] for index in found if index != sentinel]


def _set_of(patterns: Sequence[str], members: Sequence[int]) -> _Filter | None:
    made = re2.Set.SearchSet(scan_options())
    try:
        for index in members:
            made.Add(patterns[index])
        made.Add("")
        made.Compile()
    except re2.error:
        return None
    return _Filter(made, tuple(members))


def _filters(patterns: Sequence[str], members: Sequence[int]) -> tuple[list[_Filter], list[int]]:
    made = _set_of(patterns, members)
    if made is not None:
        return [made], []
    if len(members) == 1:
        return [], list(members)
    half = len(members) // 2
    left, alone = _filters(patterns, members[:half])
    right, more = _filters(patterns, members[half:])
    return left + right, alone + more


class RuleSet:
    def __init__(self, compiled: Sequence[tuple[StoredRule, CompiledRule]]) -> None:
        self.deadline: float | None = None
        self._rules = [rule for rule, _ in compiled]
        self._compiled = [rule for _, rule in compiled]
        self._groups = [rule.groupindex.get(VALUE_GROUP, 0) for _, rule in compiled]
        self._filters, self._alone = _filters(
            [rule.pattern for rule in self._rules], list(range(len(compiled)))
        )

    @property
    def unfiltered(self) -> int:
        return len(self._alone)

    def matches(self, text: str) -> list[tuple[StoredRule, list[Span]]]:
        if not text:
            return []
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise GitTimeout("rules", 0)
        asked = set(self._alone)
        for prefilter in self._filters:
            asked.update(prefilter.candidates(text))
        found = []
        for index in sorted(asked):
            group = self._groups[index]
            spans: list[Span] = []
            for match in self._compiled[index].finditer(text):
                value_start, value_end = match.span(group)
                if value_start < 0 or value_start == value_end:
                    continue
                start, end = match.span()
                spans.append((start, end, value_start, value_end))
            if spans:
                found.append((self._rules[index], spans))
        return found

    def hits(self, data: bytes) -> Matches:
        return tuple((rule, tuple(spans)) for rule, spans in self.matches(go_text(data)))


@dataclass(frozen=True)
class AddedLine:
    commit: str
    path: bytes
    line: int
    text: bytes = field(repr=False)
    matches: Matches = field(default=(), repr=False)


class _OutOfStep(GitError):
    def __init__(self, subcommand: str) -> None:
        super().__init__(subcommand, 0, f"git {subcommand} printed what the walk cannot read")


@dataclass(frozen=True, slots=True)
class _Long:
    head: bytes = field(compare=False, repr=False)
    digest: bytes = field(repr=False)


_Line = bytes | _Long


def _head(line: _Line) -> bytes:
    return line.head if isinstance(line, _Long) else line


class _Lines:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._buf = b""
        self._at = 0

    def _more(self) -> bool:
        chunk = next(self._chunks, None)
        if chunk is None:
            return False
        self._buf = self._buf[self._at :] + chunk
        self._at = 0
        return True

    def next(self, hold: int) -> _Line | None:
        while True:
            end = self._buf.find(b"\n", self._at)
            if end != -1 and end - self._at <= hold:
                line = self._buf[self._at : end]
                self._at = end + 1
                return line
            if end != -1 or len(self._buf) - self._at > hold:
                return self._long()
            if not self._more():
                if self._at == len(self._buf):
                    return None
                line = self._buf[self._at :]
                self._at = len(self._buf)
                return line

    def _long(self) -> _Long:
        head = self._buf[self._at : self._at + _LONG_HEAD]
        digest = hashlib.blake2b(digest_size=16)
        start = self._at + 1
        while True:
            end = self._buf.find(b"\n", start)
            if end != -1:
                digest.update(self._buf[start:end])
                self._at = end + 1
                return _Long(head, digest.digest())
            digest.update(self._buf[start:])
            self._buf, self._at, start = b"", 0, 0
            if not self._more():
                return _Long(head, digest.digest())


@dataclass(frozen=True)
class _Fed:
    commit: bytes
    parent: int
    parents: int


_Key = bytes | _Long


@dataclass
class _File:
    path: bytes | None
    blob: bytes | None = None
    mode: bytes | None = None
    binary: bool = False
    deleted: bool = False
    created: bool = False
    adds_lines: bool = False
    streamed: bool = False
    lines: array[int] = field(default_factory=lambda: array("I"), repr=False)
    keys: list[_Key] = field(default_factory=list, repr=False)
    removed: Counter[_Key] = field(default_factory=Counter, repr=False)
    hits: dict[bytes, bytes] = field(default_factory=dict, repr=False)

    def adds(self) -> bool:
        return self.adds_lines or (self.binary and self.blob is not None)

    def fold(self, later: "_File") -> None:
        self.blob = later.blob
        self.mode = later.mode
        self.binary = later.binary and later.blob is not None


_Net = dict[_Key, tuple[int, list[int]]]

_ENTRY = 64
_INT = sys.getsizeof(1 << 30)
_PAIR = sys.getsizeof((0, []))
_PATH_COST = 2 * _ENTRY + _PAIR + _INT
_BYTES = sys.getsizeof(b"")
_SLOT = 16
_NET_LINE = _INT + 8
_NET_KEY = _PAIR + _INT + sys.getsizeof([]) + _ENTRY


def _net(file: _File) -> _Net:
    at: dict[_Key, list[int]] = {}
    for line, key in zip(file.lines, file.keys, strict=True):
        at.setdefault(key, []).append(line)
    found: _Net = {}
    while at:
        key, lines = at.popitem()
        more = len(lines) - file.removed[key]
        if more > 0:
            found[key] = (more, lines if more == len(lines) else lines[-more:])
    return found


def _key_size(key: _Key) -> int:
    if isinstance(key, bytes):
        return sys.getsizeof(key)
    return sys.getsizeof(key) + sys.getsizeof(key.head) + sys.getsizeof(key.digest)


def _charge(path: bytes, net: _Net) -> int:
    size = sys.getsizeof(path) + _PATH_COST + sys.getsizeof(net)
    for key, (_, lines) in net.items():
        size += _key_size(key) + _PAIR + _INT + sys.getsizeof(lines) + _INT * len(lines)
    return size


def _binary_charge(path: bytes, blob: bytes) -> int:
    return sys.getsizeof(path) + sys.getsizeof(blob) + 2 * _ENTRY


def _lines_of(
    commit: bytes,
    path: bytes,
    net: _Net,
    match: Callable[[bytes], Matches],
    skipped: Counter[Gap],
) -> Iterator[AddedLine]:
    order = sorted(
        ((line, key) for key, (_, lines) in net.items() for line in lines),
        key=lambda pair: pair[0],
    )
    for line, key in order:
        if isinstance(key, _Long):
            skipped[Gap.LONG_LINES] += 1
        else:
            yield AddedLine(commit.decode("ascii"), path, line, key, match(key))


def _new_lines(
    commit: bytes,
    path: bytes,
    file: _File,
    match: Callable[[bytes], Matches],
    skipped: Counter[Gap],
) -> Iterator[AddedLine]:
    name = commit.decode("ascii")
    passed: Counter[_Key] = Counter()
    for line, key in zip(file.lines, file.keys, strict=True):
        if key in file.removed:
            passed[key] += 1
            if passed[key] <= file.removed[key]:
                continue
        if isinstance(key, _Long):
            skipped[Gap.LONG_LINES] += 1
        else:
            yield AddedLine(name, path, line, key, match(key))


def _diff_path(header: bytes) -> bytes | None:
    rest = header[len(b"diff --git ") :]
    if rest[:1] == b'"':
        first = unquote_c_style(rest)
        if first is None or first[1][:2] != b' "':
            return None
        second = unquote_c_style(first[1][1:])
        if second is None or second[1]:
            return None
        old, new = first[0], second[0]
        ok = old[:2] == b"a/" and new[:2] == b"b/" and old[2:] == new[2:] and len(old) > 2
        return old[2:] if ok else None
    if len(rest) < 7 or (len(rest) - 5) % 2:
        return None
    path = rest[2 : 2 + (len(rest) - 5) // 2]
    return path if rest == b"a/" + path + b" b/" + path else None


class _Merge:
    def __init__(self, commit: bytes, skipped: Counter[Gap]) -> None:
        self.commit = commit
        self.skipped = skipped
        self.texts: dict[bytes, tuple[_Net, int]] = {}
        self.binary: dict[bytes, bytes] = {}
        self.unseen: set[bytes] = set()
        self.held = 0
        self.over = False

    def _hold(self, path: bytes, net: _Net) -> None:
        was = self.texts.pop(path, None)
        if was is not None:
            self.held -= was[1]
        if net:
            charge = _charge(path, net)
            self.texts[path] = (net, charge)
            self.held += charge

    def _unhold_binary(self, path: bytes) -> None:
        self.held -= _binary_charge(path, self.binary.pop(path))

    def first(self, file: _File) -> None:
        if file.path is None:
            if file.adds():
                self.skipped[Gap.UNREADABLE] += 1
            return
        if file.mode == _GITLINK:
            return
        if file.binary and file.blob is not None:
            self.binary[file.path] = file.blob
            self.held += _binary_charge(file.path, file.blob)
        self._hold(file.path, _net(file))

    def begin(self) -> None:
        self.unseen = {*self.texts, *self.binary}

    def then(self, file: _File) -> None:
        if file.path is None or file.mode == _GITLINK:
            return
        if file.path not in self.texts and file.path not in self.binary:
            return
        self.unseen.discard(file.path)
        if file.binary:
            return
        if file.path in self.binary:
            self._unhold_binary(file.path)
            self._hold(file.path, _net(file))
            return
        held, _ = self.texts[file.path]
        these = _net(file)
        fewer: _Net = {}
        for key, (count, lines) in held.items():
            if key in these:
                fewer[key] = these[key] if these[key][0] < count else (count, lines)
        self._hold(file.path, fewer)

    def end(self) -> None:
        for path in self.unseen:
            if path in self.binary:
                self._unhold_binary(path)
            if path in self.texts:
                self._hold(path, {})
        self.unseen = set()

    def lines(self, match: Callable[[bytes], Matches]) -> Iterator[AddedLine]:
        for path in sorted(self.texts):
            yield from _lines_of(self.commit, path, self.texts[path][0], match, self.skipped)

    def drop(self) -> None:
        self.texts.clear()
        self.binary.clear()
        self.unseen = set()
        self.held = 0


class _Keep(Enum):
    ALL = auto()
    HELD = auto()
    NONE = auto()
    STREAM = auto()


class _Seen:
    __slots__ = ("charge", "names", "over")

    def __init__(self) -> None:
        self.names: set[bytes] = set()
        self.charge = 0
        self.over = False

    def add(self, path: bytes) -> None:
        self.names.add(path)
        self.charge += _ENTRY + sys.getsizeof(path)

    def drop(self) -> None:
        self.names = set()
        self.charge = 0
        self.over = True


class _Batch:
    __slots__ = ("charge", "waiting")

    def __init__(self) -> None:
        self.waiting: list[tuple[bytes, bytes, bytes]] = []
        self.charge = 0

    def add(self, commit: bytes, path: bytes, blob: bytes) -> None:
        self.waiting.append((commit, path, blob))
        self.charge += (
            _TRIPLE + 8 + sys.getsizeof(commit) + sys.getsizeof(path) + sys.getsizeof(blob)
        )

    def due(self) -> bool:
        return len(self.waiting) >= REREAD_BATCH or self.charge >= REREAD_BYTES

    def take(self) -> list[tuple[bytes, bytes, bytes]]:
        waiting, self.waiting, self.charge = self.waiting, [], 0
        return waiting


_TRIPLE = sys.getsizeof((b"", b"", b""))


class _Reading:
    __slots__ = (
        "base",
        "bound",
        "charge",
        "commit",
        "counted",
        "file",
        "held",
        "keep",
        "key_cost",
        "limit",
        "line_cost",
        "match",
        "merge",
        "parent",
        "path",
        "seen",
    )

    def __init__(
        self,
        commit: bytes,
        file: _File,
        merge: "_Merge | None",
        parent: int,
        match: Callable[[bytes], Matches],
        bound: int,
        seen: _Seen,
        stream: bool,
    ) -> None:
        self.commit = commit
        self.file = file
        self.parent = parent
        self.match = match
        self.bound = bound
        self.seen = seen
        self.charge = 0
        self.held: _Net | None = None
        self.counted = merge is None
        if merge is not None and merge.over:
            merge = None
        self.merge = merge
        self.path = file.path if file.path is not None else b""
        if merge is None:
            self.base, self.line_cost, self.key_cost = seen.charge, _SLOT, 0
        else:
            self.base, self.line_cost = merge.held + seen.charge, _SLOT + _NET_LINE
            self.key_cost = _NET_KEY
        self.limit = bound - self.base
        if file.path is None or file.mode == _GITLINK:
            self.keep = _Keep.NONE
        elif stream:
            self.keep = _Keep.STREAM
        elif merge is None:
            self.keep = _Keep.ALL if parent == 0 else _Keep.NONE
        elif parent == 0 or file.path in merge.binary:
            self.keep = _Keep.ALL
        elif file.path in merge.texts:
            self.keep = _Keep.HELD
            self.held = merge.texts[file.path][0]
        else:
            self.keep = _Keep.NONE

    def key(self, line: _Line) -> _Key | None:
        if isinstance(line, _Long):
            if self.held is not None and line not in self.held:
                return None
            self.charge += _key_size(line) + self.key_cost
            return line
        text = line[1:]
        hits = self.file.hits
        known = hits.get(text)
        if known is not None:
            return known
        if self.held is not None:
            if text not in self.held:
                return None
        elif not self.match(text):
            return None
        hits[text] = text
        self.charge += _BYTES + len(text) + _ENTRY + self.key_cost
        return text

    def clear(self) -> None:
        file = self.file
        file.lines = array("I")
        file.keys = []
        file.removed = Counter()
        file.hits = {}
        self.charge = 0


class _Diffs:
    def __init__(
        self,
        lines: _Lines,
        fed: deque[_Fed],
        skipped: Counter[Gap],
        batch: _Batch,
        flush: Callable[[], Iterator[AddedLine]],
        match: Callable[[bytes], Matches],
        bound: int,
    ) -> None:
        self.lines = lines
        self.fed = fed
        self.skipped = skipped
        self.batch = batch
        self.flush = flush
        self.match = match
        self.bound = bound
        self.most_held = 0
        self.line = lines.next(HEADER_LIMIT)

    def _step(self, hold: int | None = None) -> None:
        self.line = self.lines.next(HEADER_LIMIT if hold is None else hold)

    def _past(self, merge: _Merge, seen: _Seen) -> bool:
        held = merge.held + seen.charge
        self.most_held = max(self.most_held, held + self.batch.charge)
        return held > self.bound

    def _most(self, reading: _Reading) -> None:
        self.most_held = max(self.most_held, reading.base + reading.charge + self.batch.charge)

    def added(self) -> Iterator[AddedLine]:
        merge: _Merge | None = None
        while self.line is not None:
            header = self.line
            if not self.fed or not isinstance(header, bytes) or header != self.fed[0].commit:
                raise _OutOfStep("diff-tree")
            this = self.fed.popleft()
            self._step()
            if this.parents > 1 and this.parent == 0:
                merge = _Merge(this.commit, self.skipped)
            yield from self._diff(this.commit, merge, this.parent)
            if merge is not None and this.parent == this.parents - 1:
                if not merge.over:
                    yield from merge.lines(self.match)
                    for path, blob in sorted(merge.binary.items()):
                        yield from self._hand(this.commit, path, blob, merge.held)
                merge = None

    def _at_patch(self) -> bool:
        line = self.line
        return line is not None and not (isinstance(line, bytes) and OBJECT_ID.fullmatch(line))

    def _diff(self, commit: bytes, merge: _Merge | None, parent: int) -> Iterator[AddedLine]:
        seen = _Seen()
        if merge is not None and parent and not merge.over:
            merge.begin()
        pending: _File | None = None
        while pending is not None or self._at_patch():
            facts = self._facts() if pending is None else pending
            file, pending = yield from self._path(facts, commit, merge, parent, seen)
            if file.streamed:
                yield from self._single(commit, file, self._beneath(merge, seen))
                continue
            if merge is None or merge.over:
                if parent == 0:
                    yield from self._single(commit, file, seen.charge)
            elif parent == 0:
                merge.first(file)
                if self._past(merge, seen):
                    yield from self._over(merge, seen)
            else:
                merge.then(file)
                if self._past(merge, seen):
                    yield from self._over(merge, seen)
            if file.path is not None and not seen.over:
                yield from self._remember(seen, merge, file.path)
        if merge is not None and parent and not merge.over:
            merge.end()

    @staticmethod
    def _beneath(merge: _Merge | None, seen: _Seen) -> int:
        return (merge.held if merge is not None and not merge.over else 0) + seen.charge

    def _remember(self, seen: _Seen, merge: _Merge | None, path: bytes) -> Iterator[AddedLine]:
        seen.add(path)
        live = merge is not None and not merge.over
        held = self._beneath(merge, seen)
        self.most_held = max(self.most_held, held + self.batch.charge)
        if held <= self.bound:
            return
        if merge is not None and live:
            yield from self._over(merge, seen)
        if seen.charge > self.bound:
            seen.drop()

    def _path(
        self, facts: _File, commit: bytes, merge: _Merge | None, parent: int, seen: _Seen
    ) -> Generator[AddedLine, None, tuple[_File, _File | None]]:
        path = facts.path
        duplicate = path is not None and path in seen.names
        streamed = duplicate or seen.over
        reading = _Reading(commit, facts, merge, parent, self.match, self.bound, seen, streamed)
        yield from self._body(facts, reading)
        pending: _File | None = None
        if path is not None and not streamed:
            folded = False
            while self._names(path):
                later = self._facts()
                if facts.deleted and later.created and not folded:
                    yield from self._body(later, reading)
                    facts.fold(later)
                    folded = True
                    continue
                pending = later
                break
        self._most(reading)
        if duplicate:
            self.skipped[Gap.DUPLICATE_PATHS] += 1
        elif seen.over:
            self.skipped[Gap.PATHS_OVER_REPORTED] += 1
        facts.streamed = streamed
        return facts, pending

    def _names(self, path: bytes) -> bool:
        line = self.line
        return (
            isinstance(line, bytes) and line.startswith(b"diff --git ") and _diff_path(line) == path
        )

    def _over(self, merge: _Merge, seen: _Seen) -> Iterator[AddedLine]:
        merge.over = True
        self.skipped[Gap.MERGES_OVER_REPORTED] += 1
        yield from merge.lines(self.match)
        held = sorted(merge.binary.items())
        merge.drop()
        for path, blob in held:
            yield from self._hand(merge.commit, path, blob, seen.charge)

    def _spill(self, reading: _Reading) -> Iterator[AddedLine]:
        self._most(reading)
        merge = reading.merge
        if merge is not None:
            yield from self._over(merge, reading.seen)
            reading.merge = None
            reading.base = reading.seen.charge
            reading.limit = reading.bound - reading.base
            if reading.parent:
                reading.clear()
                reading.keep = _Keep.NONE
                return
        elif reading.counted:
            self.skipped[Gap.PATHS_OVER_REPORTED] += 1
        yield from _new_lines(reading.commit, reading.path, reading.file, self.match, self.skipped)
        reading.clear()
        reading.keep = _Keep.STREAM

    def _now(self, reading: _Reading, at: int, line: _Line) -> Iterator[AddedLine]:
        if isinstance(line, _Long):
            self.skipped[Gap.LONG_LINES] += 1
            return
        text = line[1:]
        found = self.match(text)
        if found:
            yield AddedLine(reading.commit.decode("ascii"), reading.path, at, text, found)

    def _hand(self, commit: bytes, path: bytes, blob: bytes, beneath: int) -> Iterator[AddedLine]:
        self.batch.add(commit, path, blob)
        self.most_held = max(self.most_held, beneath + self.batch.charge)
        if self.batch.due():
            yield from self.flush()

    def _single(self, commit: bytes, file: _File, beneath: int) -> Iterator[AddedLine]:
        if file.mode == _GITLINK:
            return
        if file.path is None:
            if file.adds():
                self.skipped[Gap.UNREADABLE] += 1
            return
        if file.binary and file.blob is not None:
            yield from self._hand(commit, file.path, file.blob, beneath)
        yield from _new_lines(commit, file.path, file, self.match, self.skipped)

    def _facts(self) -> _File:
        header = self.line
        if header is None or not _head(header).startswith(b"diff --git "):
            raise _OutOfStep("diff-tree")
        file = _File(None if isinstance(header, _Long) else _diff_path(header))
        self._step()
        while self.line is not None and self._extended(file, _head(self.line)):
            self._step()
        return file

    def _body(self, file: _File, reading: _Reading) -> Iterator[AddedLine]:
        if self.line is None:
            return
        head = _head(self.line)
        if head.startswith(b"Binary files "):
            file.binary = True
            self._step()
            return
        if not head.startswith(b"--- "):
            return
        self._step()
        if self.line is None or not _head(self.line).startswith(b"+++ "):
            raise _OutOfStep("diff-tree")
        self._step()
        while self.line is not None and _head(self.line).startswith(b"@@ "):
            yield from self._hunk(reading)

    def _extended(self, file: _File, head: bytes) -> bool:
        if isinstance(self.line, _Long):
            return False
        index = _INDEX.fullmatch(head)
        if index is not None:
            file.blob = None if index[2] == _NULL_ID else index[2]
            if index[3] is not None:
                file.mode = index[3]
            return True
        mode = _MODE.fullmatch(head)
        if mode is None:
            return False
        if mode[1] in (b"new mode", b"new file mode"):
            file.mode = mode[2]
        if mode[1] == b"new file mode":
            file.created = True
        elif mode[1] == b"deleted file mode":
            file.deleted = True
        return True

    def _hunk(self, reading: _Reading) -> Iterator[AddedLine]:
        hunk = None if self.line is None else _HUNK.match(_head(self.line))
        if hunk is None:
            raise _OutOfStep("diff-tree")
        removing = 1 if hunk[1] is None else int(hunk[1])
        adding = 1 if hunk[3] is None else int(hunk[3])
        at = int(hunk[2])
        file = reading.file
        self._step(_LINE_HOLD if removing or adding else HEADER_LIMIT)
        while removing or adding:
            if self.line is None:
                raise _OutOfStep("diff-tree")
            line = self.line
            marker = _head(line)[:1]
            keep = reading.keep
            if marker == b"-" and removing:
                if keep is _Keep.ALL or keep is _Keep.HELD:
                    key = reading.key(line)
                    if key is not None:
                        if key not in file.removed:
                            reading.charge += _ENTRY
                        file.removed[key] += 1
                        if reading.charge > reading.limit:
                            yield from self._spill(reading)
                removing -= 1
            elif marker == b"+" and adding:
                file.adds_lines = True
                if keep is _Keep.STREAM:
                    yield from self._now(reading, at, line)
                elif keep is _Keep.ALL or keep is _Keep.HELD:
                    key = reading.key(line)
                    if key is not None:
                        file.lines.append(at)
                        file.keys.append(key)
                        reading.charge += reading.line_cost
                        if reading.charge > reading.limit:
                            yield from self._spill(reading)
                at += 1
                adding -= 1
            elif marker != b"\\":
                raise _OutOfStep("diff-tree")
            self._step(_LINE_HOLD if removing or adding else HEADER_LIMIT)
        while self.line is not None and _head(self.line).startswith(b"\\"):
            self._step()


class _Walk:
    def __init__(
        self,
        runner: GitRunner,
        shadow: Path,
        *,
        timeout: float,
        cancel: threading.Event | None,
        skipped: Counter[Gap],
        rules: RuleSet,
        bound: int = MAX_MERGE_HELD_BYTES,
    ) -> None:
        self.runner = runner
        self.shadow = shadow
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.cancel = cancel
        self.skipped = skipped
        self.rules = rules
        self.bound = bound
        self.most_held = 0
        self.batch = _Batch()

    def left(self, subcommand: str) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise GitTimeout(subcommand, self.timeout)
        if self.cancel is not None and self.cancel.is_set():
            raise GitCancelled(subcommand)
        return left

    def diffs(self, commits: Sequence[Sequence[bytes]]) -> Iterator[AddedLine]:
        fed: deque[_Fed] = deque()
        stdin = bytearray()
        for ids in commits:
            commit, parents = ids[0], ids[1:]
            if len(parents) < 2:
                fed.append(_Fed(commit, 0, 1))
                stdin += b" ".join(ids) + b"\n"
                continue
            for n, parent in enumerate(parents):
                fed.append(_Fed(commit, n, len(parents)))
                stdin += commit + b" " + parent + b"\n"
        with self.runner.stream(
            list(_DIFF_TREE),
            cwd=self.runner.private_dir,
            timeout=self.left("diff-tree"),
            cancel=self.cancel,
            stdin=bytes(stdin),
            extra_env=git_env(self.shadow),
            extra_config=_patch_config(),
        ) as chunks:
            diffs = _Diffs(
                _Lines(chunks),
                fed,
                self.skipped,
                self.batch,
                self.due,
                self.rules.hits,
                self.bound,
            )
            try:
                yield from diffs.added()
            finally:
                self.most_held = max(self.most_held, diffs.most_held)
        if fed:
            raise _OutOfStep("diff-tree")

    def due(self) -> Iterator[AddedLine]:
        yield from self.reread()

    def added(self) -> Generator[AddedLine]:
        with self.runner.stream(
            list(_REV_LIST),
            cwd=self.runner.private_dir,
            timeout=self.timeout,
            cancel=self.cancel,
            extra_env=git_env(self.shadow),
        ) as chunks:
            for batch in _batches(_commits(_Lines(chunks))):
                yield from self.diffs(batch)
        yield from self.reread()

    def reread(self) -> Iterator[AddedLine]:
        waiting = self.batch.take()
        if not waiting:
            return
        ids = [blob.decode("ascii") for blob in dict.fromkeys(blob for _, _, blob in waiting)]
        sizes = self._sizes(ids)
        small = [blob for blob in ids if sizes.get(blob, MAX_VIEW_BYTES + 1) <= MAX_VIEW_BYTES]
        by_blob: dict[str, list[tuple[bytes, bytes]]] = {}
        for commit, path, wanted in waiting:
            name = wanted.decode("ascii")
            if name not in sizes:
                self.skipped[Gap.UNREADABLE] += 1
            elif sizes[name] > MAX_VIEW_BYTES:
                self.skipped[Gap.TOO_LARGE] += 1
            else:
                by_blob.setdefault(name, []).append((commit, path))
        read: set[str] = set()
        for blob, data in object_batches(
            self.runner,
            self.shadow,
            small,
            kind="blob",
            max_size=MAX_VIEW_BYTES,
            timeout=self.left("cat-file"),
            cancel=self.cancel,
        ):
            read.add(blob)
            for commit, path in by_blob.get(blob, []):
                yield from self._whole(commit, path, data)
        self.skipped[Gap.UNREADABLE] += sum(
            len(places) for blob, places in by_blob.items() if blob not in read
        )

    def _whole(self, commit: bytes, path: bytes, data: bytes) -> Iterator[AddedLine]:
        if b"\0" in data[:BINARY_PROBE_BYTES]:
            self.skipped[Gap.BINARY] += 1
            return
        lines = data.split(b"\n")
        if lines and not lines[-1]:
            lines.pop()
        for number, text in enumerate(lines, start=1):
            if len(text) > MATCH_LIMIT:
                self.skipped[Gap.LONG_LINES] += 1
                continue
            found = self.rules.hits(text)
            if found:
                yield AddedLine(commit.decode("ascii"), path, number, text, found)

    def _sizes(self, ids: Sequence[str]) -> dict[str, int]:
        out = self.runner.run(
            ["cat-file", "--batch-check"],
            cwd=self.runner.private_dir,
            stdin="".join(f"{blob}\n" for blob in ids).encode("ascii"),
            timeout=self.left("cat-file"),
            cancel=self.cancel,
            extra_env=git_env(self.shadow),
            max_stdout=len(ids) * 80,
        )
        asked = set(ids)
        sizes: dict[str, int] = {}
        for line in out.split(b"\n"):
            parts = line.split(b" ")
            if len(parts) == 3 and parts[1] == b"blob" and parts[2].isdigit():
                blob = parts[0].decode("ascii", "replace")
                if blob in asked:
                    sizes[blob] = int(parts[2])
        return sizes


def _commits(lines: _Lines) -> Iterator[list[bytes]]:
    while (line := lines.next(HEADER_LIMIT)) is not None:
        if isinstance(line, _Long):
            raise _OutOfStep("rev-list")
        ids = line.split(b" ")
        if not all(OBJECT_ID.fullmatch(one) for one in ids):
            raise _OutOfStep("rev-list")
        yield ids


def _patch_config() -> tuple[tuple[str, str], ...]:
    return (("core.quotePath", "true"), ("core.bigFileThreshold", str(MAX_DIFFED_FILE_BYTES)))


def _batches(commits: Iterable[list[bytes]]) -> Iterator[list[list[bytes]]]:
    batch: list[list[bytes]] = []
    fed = 0
    for ids in commits:
        lines = max(1, len(ids) - 1) if len(ids) > 2 else 1
        if batch and fed + lines > LINES_A_CALL:
            yield batch
            batch, fed = [], 0
        batch.append(ids)
        fed += lines
    if batch:
        yield batch


def added_lines(
    runner: GitRunner,
    shadow: Path,
    *,
    timeout: float,
    cancel: threading.Event | None,
    skipped: Counter[Gap],
    rules: RuleSet,
    merge_held_bytes: int = MAX_MERGE_HELD_BYTES,
) -> Generator[AddedLine]:
    walk = _Walk(
        runner,
        shadow,
        timeout=timeout,
        cancel=cancel,
        skipped=skipped,
        rules=rules,
        bound=merge_held_bytes,
    )
    yield from walk.added()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _hit(added: AddedLine, rule: StoredRule, spans: Sequence[Span]) -> bytes:
    record = {
        "commit": added.commit,
        "path": _b64(added.path),
        "line": added.line,
        "rule": rule.id,
        "kind": rule.name,
        "spans": [list(span) for span in spans],
        "text": _b64(added.text),
    }
    return json.dumps(record, separators=(",", ":")).encode() + b"\n"


def _summary(gaps: Mapping[str, int]) -> bytes:
    return json.dumps({"gaps": dict(gaps)}, separators=(",", ":")).encode() + b"\n"


def compile_rule_set(stored: Sequence[StoredRule]) -> tuple[RuleSet | None, int]:
    usable: list[tuple[StoredRule, CompiledRule]] = []
    left_out = 0
    budget = run_budget(len(stored))
    for rule in stored:
        compiled = compile_rule(rule.pattern, max_mem=budget)
        if isinstance(compiled, RuleRefusal):
            left_out += 1
        else:
            usable.append((rule, compiled))
    return (RuleSet(usable) if usable else None), left_out


def gap_counts(skipped: Counter[Gap], left_out: int) -> dict[str, int]:
    return {**{gap.value: skipped[gap] for gap in Gap}, "rules_left_out": left_out}


def write_hits_file(
    runner: GitRunner,
    shadow: Path,
    hits: Path,
    rule_set: RuleSet,
    left_out: int,
    *,
    timeout: float,
    cancel: threading.Event,
    merge_held_bytes: int,
) -> dict[str, int]:
    skipped: Counter[Gap] = Counter()
    rule_set.deadline = time.monotonic() + timeout
    lines = added_lines(
        runner,
        shadow,
        timeout=timeout,
        cancel=cancel,
        skipped=skipped,
        rules=rule_set,
        merge_held_bytes=merge_held_bytes,
    )
    with (
        os.fdopen(os.open(hits, _NEW_FILE, 0o600), "wb") as out,
        contextlib.closing(lines),
    ):
        for added in lines:
            for rule, spans in added.matches:
                out.write(_hit(added, rule, spans))
        gaps = gap_counts(skipped, left_out)
        out.write(_summary(gaps))
    return gaps
