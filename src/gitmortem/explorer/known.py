import heapq
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from itertools import islice

from gitmortem.explorer.commits import MAX_SUBJECT_CHARS
from gitmortem.triage.context import (
    Segment,
    clean_file_text,
    clean_line,
    content_end,
    marked_spans,
)
from gitmortem.triage.known_values import (
    ANCHOR_CHARS,
    MAX_KNOWN_PER_REPO,
    MAX_KNOWN_PIECES,
    KnownIndex,
    Occurrence,
    ValueFinder,
    known_values,
)
from gitmortem.triage.subjects import Subject

__all__ = [
    "ANCHOR_CHARS",
    "MAX_KNOWN_PER_REPO",
    "MAX_KNOWN_PIECES",
    "MAX_MARKS",
    "MESSAGE_SHOWN_BYTES",
    "KnownIndex",
    "Mark",
    "Marked",
    "ValueFinder",
    "as_in_files",
    "known_values",
    "mark",
    "marked_message",
    "marked_subject",
    "merged_marks",
]

MAX_MARKS = 10_000
MESSAGE_SHOWN_BYTES = 4096

Lines = tuple[tuple[Segment, ...], ...]


def as_in_files(known: Mapping[Subject, str]) -> dict[Subject, str]:
    return {subject: clean_file_text(value) for subject, value in known.items()}


@dataclass(frozen=True)
class Mark:
    line: int
    line_start: int
    start: int
    end: int
    value: str = field(default="", compare=False, repr=False)


@dataclass(frozen=True)
class Marked:
    marks: tuple[Mark, ...]
    truncated: bool
    found: Mapping[str, int] = field(default_factory=dict, compare=False, repr=False)


def _by_line(
    text: str, start: int, end: int, line: int, line_start: int, value: str
) -> Iterator[Mark]:
    while (stop := text.find("\n", start, end)) != -1:
        if start < stop:
            yield Mark(line, line_start, start, stop, value)
        start = line_start = stop + 1
        line += 1
    if start < end:
        yield Mark(line, line_start, start, end, value)


def mark(index: ValueFinder, text: str) -> Marked:
    latest_first: list[tuple[int, int]] = []
    held: dict[tuple[int, int], str] = {}
    found: dict[str, int] = {}
    dropped = False
    for start, end, value in index.occurrences(text):
        earliest = found.get(value)
        if earliest is None or start < earliest:
            found[value] = start
        if (start, end) in held:
            continue
        if len(latest_first) <= MAX_MARKS:
            heapq.heappush(latest_first, (-start, -end))
            held[(start, end)] = value
            continue
        dropped = True
        latest = (-latest_first[0][0], -latest_first[0][1])
        if (start, end) < latest:
            heapq.heapreplace(latest_first, (-start, -end))
            del held[latest]
            held[(start, end)] = value
    first = sorted((-start, -end) for start, end in latest_first)
    runs = []
    line, line_start, counted = 1, 0, 0
    for start, end in first:
        if breaks := text.count("\n", counted, start):
            line += breaks
            line_start = text.rfind("\n", counted, start) + 1
        counted = start
        runs.append(_by_line(text, start, end, line, line_start, held[(start, end)]))
    kept = list(islice(heapq.merge(*runs, key=lambda m: (m.start, m.end)), MAX_MARKS + 1))
    return Marked(
        marks=tuple(kept[:MAX_MARKS]), truncated=dropped or len(kept) > MAX_MARKS, found=found
    )


def merged_marks(*parts: Marked) -> Marked:
    kept: list[Mark] = []
    for each in heapq.merge(*(part.marks for part in parts), key=lambda m: (m.start, m.end)):
        if kept and (kept[-1].start, kept[-1].end) == (each.start, each.end):
            continue
        kept.append(each)
        if len(kept) > MAX_MARKS:
            break
    truncated = any(part.truncated for part in parts) or len(kept) > MAX_MARKS
    return Marked(marks=tuple(kept[:MAX_MARKS]), truncated=truncated)


def _shown_stop(message: str, most: int) -> int:
    left, start = most, 0
    while True:
        end = message.find("\n", start)
        end = len(message) if end == -1 else end
        close = content_end(message, start, end)
        shown = clean_line(message[start : min(close, start + left + 1)]).encode("utf-8", "replace")
        if len(shown) > left:
            return start + len(shown[:left].decode("utf-8", "ignore"))
        left -= len(shown)
        if end == len(message) or left < 1:
            return end
        left -= 1
        start = end + 1


def marked_message(index: KnownIndex, message: str) -> tuple[Lines, bool]:
    stop = _shown_stop(message, MESSAGE_SHOWN_BYTES)
    found = list(index.occurrences(message))
    return marked_spans(message, found, stop=stop), stop < len(message)


def marked_subject(message: str, found: Collection[Occurrence]) -> tuple[tuple[Segment, ...], bool]:
    end = message.find("\n")
    content = content_end(message, 0, len(message) if end == -1 else end)
    stop = min(content, MAX_SUBJECT_CHARS)
    lines = marked_spans(message, found, stop=stop)
    return (lines[0] if lines else ()), content > MAX_SUBJECT_CHARS
