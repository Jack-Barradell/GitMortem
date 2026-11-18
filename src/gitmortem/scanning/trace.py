import json
import os
import re
import stat
from collections import Counter
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, Strict

__all__ = [
    "MAX_END_KINDS",
    "MAX_TRACE_BYTES",
    "MAX_TRACE_FILES",
    "MAX_TRACE_LINE",
    "READERS",
    "TRACE_DIR",
    "GitEnd",
    "GitTrace",
    "TraceProblem",
    "TraceUnread",
    "TraceUnreadReason",
    "TraceVerdict",
    "judge_trace",
    "make_trace_dir",
    "trace_dir",
]

TRACE_DIR = ".gitmortem-trace2"
MAX_TRACE_FILES = 100_000
MAX_TRACE_BYTES = 4 << 30
MAX_TRACE_LINE = 64 << 10
MAX_END_KINDS = 20
READERS = frozenset({"log", "rev-list", "grep", "diff-tree", "cat-file", "show", "diff"})
_DIED = 128
_CHUNK = 64 << 10
_WANTED = re.compile(rb'"event"[ \t]*:[ \t]*"(?:cmd_name|exit|atexit|signal)"')
_READ = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)

Count = Annotated[int, Strict(), Field(ge=0)]
Number = Annotated[int, Strict()]


class TraceProblem(StrEnum):
    NONE_RAN = "none_ran"
    UNREADABLE = "unreadable"
    TOO_MANY = "too_many"


class TraceUnreadReason(StrEnum):
    NOT_A_FILE = "not_a_file"
    TOO_LARGE = "too_large"
    REFUSED = "refused"
    LISTING = "listing"


class TraceUnread(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: TraceUnreadReason
    error: Number | None = None


class GitEnd(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    command: str
    code: Number | None
    signal: Number | None
    count: Count


class GitTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    readers: Count
    ends: tuple[GitEnd, ...] = ()
    more: Count = 0
    problem: TraceProblem | None = None
    unread: TraceUnread | None = None
    needed: str | None = None


_EndKey = tuple[str, int | None, int | None]


@dataclass(frozen=True)
class TraceVerdict:
    readers: int
    failed: int
    unreadable: bool
    ended: frozenset[str] = frozenset()
    ends: tuple[tuple[_EndKey, int], ...] = ()
    too_many: bool = False
    unread: TraceUnread | None = None

    @property
    def finished(self) -> bool:
        return self.readers > 0 and self.failed == 0 and not self.unreadable

    @property
    def problem(self) -> TraceProblem | None:
        if self.too_many:
            return TraceProblem.TOO_MANY
        if self.unreadable:
            return TraceProblem.UNREADABLE
        if self.readers == 0:
            return TraceProblem.NONE_RAN
        return None

    def summary(self, *, needed: str | None = None) -> GitTrace:
        kept = self.ends[:MAX_END_KINDS]
        return GitTrace(
            readers=self.readers,
            ends=tuple(
                GitEnd(command=command, code=code, signal=signal, count=count)
                for (command, code, signal), count in kept
            ),
            more=sum(count for _, count in self.ends[MAX_END_KINDS:]),
            problem=self.problem,
            unread=None if self.too_many else self.unread,
            needed=None if needed is None or needed in self.ended else needed,
        )


def trace_dir(private: Path) -> Path:
    return private / TRACE_DIR


def make_trace_dir(private: Path) -> Path:
    folder = trace_dir(private)
    folder.mkdir(mode=0o700)
    return folder


class _TooLarge(Exception):
    pass


def _error_number(error: OSError) -> int | None:
    number = getattr(error, "winerror", None)
    if not isinstance(number, int):
        number = error.errno
    return number if isinstance(number, int) else None


def _matching(region: bytes) -> Iterator[bytes]:
    done = -1
    for found in _WANTED.finditer(region):
        if found.start() < done:
            continue
        start = region.rfind(b"\n", 0, found.start()) + 1
        end = region.find(b"\n", found.end())
        done = len(region) if end == -1 else end
        if done - start <= MAX_TRACE_LINE:
            yield region[start:done]


def _wanted_lines(fd: int) -> Iterator[bytes]:
    carry = b""
    skipping = False
    total = 0
    while chunk := os.read(fd, _CHUNK):
        total += len(chunk)
        if total > MAX_TRACE_BYTES:
            raise _TooLarge
        if skipping:
            newline = chunk.find(b"\n")
            if newline == -1:
                continue
            chunk = chunk[newline + 1 :]
            skipping = False
        held = carry + chunk
        cut = held.rfind(b"\n") + 1
        yield from _matching(held[:cut])
        carry = held[cut:]
        if len(carry) > MAX_TRACE_LINE:
            carry = b""
            skipping = True
    if not skipping:
        yield from _matching(carry)


def _read(path: str) -> "_Process | TraceUnread":
    try:
        fd = os.open(path, _READ)
    except OSError as error:
        return TraceUnread(reason=TraceUnreadReason.REFUSED, error=_error_number(error))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return TraceUnread(reason=TraceUnreadReason.NOT_A_FILE)
        return _process(_wanted_lines(fd))
    except _TooLarge:
        return TraceUnread(reason=TraceUnreadReason.TOO_LARGE)
    except OSError as error:
        return TraceUnread(reason=TraceUnreadReason.REFUSED, error=_error_number(error))
    finally:
        os.close(fd)


@dataclass(frozen=True)
class _Process:
    name: str | None
    code: int | None
    signal: int | None

    @property
    def ended(self) -> bool:
        return self.code is not None and self.code < _DIED and self.signal is None


def _process(lines: Iterable[bytes]) -> _Process:
    name: str | None = None
    code: int | None = None
    signal: int | None = None
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        if kind == "cmd_name" and isinstance(event.get("name"), str):
            name = event["name"]
        elif kind in ("exit", "atexit") and _is_number(event.get("code")):
            code = event["code"]
        elif kind == "signal":
            signo = event.get("signo")
            signal = signo if _is_number(signo) else 0
    return _Process(name, code, signal)


def _is_number(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass
class _Tally:
    seen: int = 0
    ended: set[str] = field(default_factory=set)
    ends: Counter[_EndKey] = field(default_factory=Counter)

    def verdict(self, *, unread: TraceUnread | None = None, too_many: bool = False) -> TraceVerdict:
        ranked = sorted(self.ends.items(), key=lambda item: (-item[1], _order(item[0])))
        return TraceVerdict(
            self.seen,
            self.ends.total(),
            unreadable=unread is not None or too_many,
            ended=frozenset(self.ended),
            ends=tuple(ranked),
            too_many=too_many,
            unread=unread,
        )


def _order(key: _EndKey) -> tuple[str, int, int]:
    command, code, signal = key
    return command, -1 if code is None else code, -1 if signal is None else signal


def judge_trace(folder: Path, *, readers: Collection[str] = READERS) -> TraceVerdict:
    tally = _Tally()
    try:
        with os.scandir(folder) as listing:
            for count, entry in enumerate(listing, start=1):
                if count > MAX_TRACE_FILES:
                    return tally.verdict(too_many=True)
                if not entry.is_file(follow_symlinks=False):
                    return tally.verdict(unread=TraceUnread(reason=TraceUnreadReason.NOT_A_FILE))
                process = _read(entry.path)
                if isinstance(process, TraceUnread):
                    return tally.verdict(unread=process)
                name = process.name
                if name is None or name not in readers:
                    continue
                tally.seen += 1
                if process.ended:
                    tally.ended.add(name)
                else:
                    tally.ends[(name, process.code, process.signal)] += 1
    except OSError as error:
        unread = TraceUnread(reason=TraceUnreadReason.LISTING, error=_error_number(error))
        return tally.verdict(unread=unread)
    return tally.verdict()
