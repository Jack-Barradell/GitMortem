import math
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from itertools import batched, pairwise
from typing import Any

import re2
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import Finding, Secret
from gitmortem.triage import values
from gitmortem.triage.subjects import Subject, SubjectKind

__all__ = [
    "ANCHOR_CHARS",
    "COMPARE_CHARS",
    "MAX_KNOWN_BYTES",
    "MAX_KNOWN_PER_REPO",
    "MAX_KNOWN_PIECES",
    "MAX_MARK_WORK",
    "RE2_MAX_MEM",
    "SAMPLES_A_UNIT",
    "SHORTS_A_PROGRAM",
    "KnownIndex",
    "MarkWork",
    "Occurrence",
    "TooMuchToMark",
    "ValueFinder",
    "known_in",
    "known_values",
]

MAX_KNOWN_PER_REPO = 100_000
SHORT_PROGRAMS_KEPT = 64
MAX_KNOWN_BYTES = 256 << 20
MAX_KNOWN_PIECES = 1_000_000
ANCHOR_CHARS = 8
RE2_MAX_MEM = 64 << 20
SHORTS_A_PROGRAM = 10_000
CROWDED = 16
COMPARE_CHARS = 256
SAMPLES_A_UNIT = 4
MAX_MARK_WORK = 20_000_000
_PIECE_STRIP = "\r \t"

Occurrence = tuple[int, int, str]


class TooMuchToMark(values.TooManyToDecrypt):
    MESSAGE = "Too many known values occur in what was asked for to mark them all."


class MarkWork:
    def __init__(self, limit: int | None = None) -> None:
        self.limit = MAX_MARK_WORK if limit is None else limit
        self.done = 0

    def __repr__(self) -> str:
        return f"MarkWork({self.done} of {self.limit})"

    def spend(self, amount: int) -> None:
        self.done += amount
        if self.done > self.limit:
            raise TooMuchToMark


def _options() -> re2.Options:
    options = re2.Options()
    options.max_mem = RE2_MAX_MEM
    options.log_errors = False
    return options


class _Anchors:
    def __init__(self, strings: Iterable[str]) -> None:
        self.strings = sorted(set(strings))
        shortest = min(map(len, self.strings), default=ANCHOR_CHARS)
        self._widest = shortest - ANCHOR_CHARS + 1
        self._step = 0
        self._bases: list[int] = []
        self._first: dict[str, int] = {}
        self._more: dict[str, list[int]] = {}

    def __len__(self) -> int:
        return len(self.strings)

    def step(self, size: int) -> int:
        if not self.strings:
            return 1
        wanted = round(math.sqrt(size / (4 * len(self.strings))))
        return max(1, min(wanted, self._widest))

    def _based(self, step: int) -> list[int]:
        candidates = []
        for string in self.strings:
            latest = len(string) - ANCHOR_CHARS - step + 1
            candidates.append(sorted({0, latest // 2, latest}))
        shared = Counter(
            string[at : at + ANCHOR_CHARS]
            for string, places in zip(self.strings, candidates, strict=True)
            for at in places
        )
        return [
            min(places, key=lambda at: shared[string[at : at + ANCHOR_CHARS]])
            for string, places in zip(self.strings, candidates, strict=True)
        ]

    def _spread(self, step: int, crowded: Iterable[int]) -> dict[int, int]:
        span = step + ANCHOR_CHARS - 1
        judged: list[tuple[int, list[int], list[list[str]]]] = []
        for number in crowded:
            string = self.strings[number]
            latest = len(string) - span
            places = sorted({latest * k // 7 for k in range(8)})
            blocks = [
                [
                    *(string[b : b + ANCHOR_CHARS] for b in range(at, at + span, ANCHOR_CHARS)),
                    string[at + span - ANCHOR_CHARS : at + span],
                ]
                for at in places
            ]
            judged.append((number, places, blocks))
        shared = Counter(block for _, _, every in judged for each in every for block in each)
        return {
            number: places[min(range(len(places)), key=lambda n: max(shared[b] for b in blocks[n]))]
            for number, places, blocks in judged
        }

    def _build(
        self, step: int, bases: Sequence[int]
    ) -> tuple[dict[str, int], dict[str, list[int]]]:
        first: dict[str, int] = {}
        more: dict[str, list[int]] = {}
        for place, (string, base) in enumerate(zip(self.strings, bases, strict=True)):
            for offset in range(step):
                piece = string[base + offset : base + offset + ANCHOR_CHARS]
                code = place * step + offset
                if piece in first:
                    more.setdefault(piece, []).append(code)
                else:
                    first[piece] = code
        return first, more

    def _anchored(self, step: int) -> tuple[dict[str, int], dict[str, list[int]]]:
        if step != self._step:
            bases = self._based(step)
            first, more = self._build(step, bases)
            crowded = {
                code // step
                for piece, codes in more.items()
                if len(codes) + 1 >= CROWDED
                for code in (first[piece], *codes)
            }
            if crowded:
                for number, base in self._spread(step, crowded).items():
                    bases[number] = base
                first, more = self._build(step, bases)
            self._step, self._bases, self._first, self._more = step, bases, first, more
        return self._first, self._more

    def samples(self, size: int, step: int) -> int:
        return max(0, (size - ANCHOR_CHARS) // step + 1)

    def occurrences(
        self, text: str, step: int, work: MarkWork, *, sampled: bool = False
    ) -> Iterator[Occurrence]:
        if not self.strings:
            return
        step = max(1, min(step, self._widest))
        size = len(text)
        if not sampled:
            work.spend(1 + self.samples(size, step) // SAMPLES_A_UNIT)
        first, more = self._anchored(step)
        bases = self._bases
        for sample in range(0, size - ANCHOR_CHARS + 1, step):
            piece = text[sample : sample + ANCHOR_CHARS]
            code = first.get(piece)
            if code is None:
                continue
            for each in (code, *more.get(piece, ())):
                place, offset = divmod(each, step)
                string = self.strings[place]
                start = sample - bases[place] - offset
                reach = len(string) if 0 <= start <= size - len(string) else 0
                work.spend(1 + reach // COMPARE_CHARS)
                if reach and text.startswith(string, start):
                    yield start, start + len(string), string


class _Shorts:
    def __init__(self, strings: Iterable[str]) -> None:
        self.strings = sorted(set(strings))
        self._by_bytes = {string.encode(): string for string in self.strings}
        self._sets: list[tuple[re2.Set, tuple[str, ...]]] | None = None
        self._programs: dict[tuple[str, ...], Any] = {}

    def __bool__(self) -> bool:
        return bool(self.strings)

    def present(self, data: bytes) -> list[str]:
        if self._sets is None:
            self._sets = []
            for chunk in batched(self.strings, SHORTS_A_PROGRAM):
                found = re2.Set.SearchSet(_options())
                for string in chunk:
                    found.Add(re2.escape(string.encode()))
                found.Compile()
                self._sets.append((found, chunk))
        return [chunk[n] for found, chunk in self._sets for n in found.Match(data) or ()]

    def spans(self, data: bytes, work: MarkWork) -> list[tuple[int, int, str]]:
        by_length: dict[int, list[str]] = {}
        for string in sorted(self.present(data)):
            by_length.setdefault(len(string), []).append(string)
        spans = []
        for same in by_length.values():
            for chunk in batched(same, SHORTS_A_PROGRAM):
                program = self._program(chunk)
                at = 0
                while (match := program.search(data, at)) is not None:
                    work.spend(1)
                    start, end = match.start(), match.end()
                    spans.append((start, end, self._by_bytes[data[start:end]]))
                    at = start + 1
        spans.sort()
        return spans

    def _program(self, chunk: tuple[str, ...]) -> Any:
        program = self._programs.get(chunk)
        if program is None:
            if len(self._programs) >= SHORT_PROGRAMS_KEPT:
                self._programs.clear()
            either = b"|".join(re2.escape(string.encode()) for string in chunk)
            program = self._programs[chunk] = re2._Regexp(either, _options())
        return program

    def occurrences(self, text: str, work: MarkWork) -> Iterator[Occurrence]:
        data = text.encode()
        if text.isascii():
            yield from self.spans(data, work)
            return
        point = at = 0
        for start, _, string in self.spans(data, work):
            point += len(data[at:start].decode())
            at = start
            yield point, point + len(string), string


def _pieces_of(value: str) -> tuple[tuple[int, str], ...]:
    lines = (line.strip(_PIECE_STRIP) for line in value.split("\n"))
    return tuple((n, line) for n, line in enumerate(lines) if len(line) >= ANCHOR_CHARS)


def _lines_at(text: str, places: Iterable[int]) -> dict[int, int]:
    lines: dict[int, int] = {}
    line = counted = 0
    for place in sorted(set(places)):
        line += text.count("\n", counted, place)
        counted = place
        lines[place] = line
    return lines


class ValueFinder:
    def __init__(self, values_held: Iterable[str], *, work: MarkWork | None = None) -> None:
        self.work = MarkWork() if work is None else work
        held = {value for value in values_held if value}
        self.values = tuple(sorted(held))
        self.longest = max(map(len, held), default=0)
        self._shorts = _Shorts(value for value in held if len(value) < ANCHOR_CHARS)
        self._long = _Anchors(value for value in held if len(value) >= ANCHOR_CHARS)
        self._lines: dict[str, tuple[tuple[int, str], ...]] = {}
        owners: dict[str, set[str]] = {}
        count = 0
        for value in self.values:
            if "\n" not in value:
                continue
            kept = _pieces_of(value)
            count += len(kept)
            if count > MAX_KNOWN_PIECES:
                raise values.TooManyToDecrypt
            if kept:
                self._lines[value] = kept
                for _, piece in kept:
                    owners.setdefault(piece, set()).add(value)
        self._owners = {piece: frozenset(held_by) for piece, held_by in owners.items()}
        self._piece_sets = {
            value: frozenset(piece for _, piece in kept) for value, kept in self._lines.items()
        }
        self._gap = {
            value: max((b - a for (a, _), (b, _) in pairwise(kept)), default=1)
            for value, kept in self._lines.items()
        }
        self._pieces = _Anchors(owners)
        self._forms: _Forms | None = None
        self._starts: dict[int, tuple[list[tuple[str, bool]], set[str]]] = {}

    def __len__(self) -> int:
        return len(self.values)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self)} values)"

    def step(self, size: int) -> int:
        return self._long.step(size)

    def _named(self) -> "_Forms":
        if self._forms is None:
            holders: dict[str, list[str]] = {piece: [] for piece in self._owners}
            held: dict[str, set[str]] = {}
            hosts = self._long.strings
            scan = _Anchors(self._owners)
            step = scan.step(sum(map(len, hosts)))
            samples = sum(scan.samples(len(host), step) for host in hosts)
            self.work.spend(1 + samples // SAMPLES_A_UNIT)
            for host in hosts:
                for _, _, piece in scan.occurrences(host, step, self.work, sampled=True):
                    if host not in held or piece not in held[host]:
                        holders[piece].append(host)
                        held.setdefault(host, set()).add(piece)
            self._forms = _Forms(self._piece_sets, holders, held, self.work)
        return self._forms

    def _in_runs(self, text: str, size: int, whole: Sequence[Occurrence]) -> Iterator[Occurrence]:
        work = self.work
        found = list(self._pieces.occurrences(text, self._pieces.step(size), work))
        if not found:
            return
        forms = self._named()
        spans: dict[str, list[tuple[int, int]]] = {}
        for start, end, value in whole:
            spans.setdefault(value, []).append((start, end))
        covers = {value: _cover(held) for value, held in spans.items()}
        lines = _lines_at(text, (start for start, _, _ in found))
        on_line: dict[int, dict[str, list[tuple[int, int]]]] = {}
        seeds: dict[str, set[int]] = {}
        left: list[Occurrence] = []
        naming = [forms.named(piece) for _, _, piece in found]
        work.spend(sum(map(len, naming)))
        for (start, end, piece), names in zip(found, naming, strict=True):
            line = lines[start]
            on_line.setdefault(line, {}).setdefault(piece, []).append((start, end))
            named = False
            for value in names:
                if _inside(covers.get(value), start, end):
                    continue
                named = True
                yield start, end, value
                if value in self._lines:
                    seeds.setdefault(value, set()).add(line)
            if not named:
                left.append((start, end, piece))
        if not left or not seeds:
            return
        events: list[tuple[int, int, str]] = []
        for value, seeded in seeds.items():
            pieces, cover = self._piece_sets[value], covers.get(value)
            for low, high in _runs(on_line, seeded, pieces, cover, self._gap[value], work):
                events += [(low, 1, value), (high + 1, 0, value)]
        events.sort()
        active: dict[str, int] = {}
        candidates: dict[str, list[tuple[int, str]]] = {}
        at = 0
        for start, end, piece in sorted(left):
            line = lines[start]
            if at < len(events) and events[at][0] <= line:
                while at < len(events) and events[at][0] <= line:
                    first, starting, value = events[at]
                    at += 1
                    if starting:
                        active[value] = first
                    else:
                        del active[value]
                candidates.clear()
            if not active:
                continue
            chosen = candidates.get(piece)
            if chosen is None:
                owners = self._owners[piece]
                if len(active) <= len(owners):
                    work.spend(len(active))
                    chosen = [(first, v) for v, first in active.items() if v in owners]
                else:
                    work.spend(len(owners))
                    chosen = [(active[v], v) for v in owners if v in active]
                chosen.sort(reverse=True)
                candidates[piece] = chosen
            for _, value in chosen:
                work.spend(1)
                if not _inside(covers.get(value), start, end):
                    yield start, end, value
                    break

    def occurrences(self, text: str, *, size: int | None = None) -> Iterator[Occurrence]:
        size = len(text) if size is None else size
        whole: list[Occurrence] = []
        if self._shorts:
            whole.extend(self._shorts.occurrences(text, self.work))
        whole.extend(self._long.occurrences(text, self._long.step(size), self.work))
        yield from whole
        if self._pieces:
            yield from self._in_runs(text, size, whole)

    def values_in(self, texts: Iterable[str], *, size: int | None = None) -> set[str]:
        given = list(texts)
        size = sum(map(len, given)) if size is None else size
        found: set[str] = set()
        pieces: set[str] = set()
        for text in given:
            if self._shorts:
                found.update(self._shorts.present(text.encode()))
            found.update(
                value for _, _, value in self._long.occurrences(text, self.step(size), self.work)
            )
            if self._pieces:
                step = self._pieces.step(size)
                pieces.update(
                    piece for _, _, piece in self._pieces.occurrences(text, step, self.work)
                )
        if pieces:
            forms = self._named()
            for piece in pieces:
                names = forms.named(piece)
                self.work.spend(len(names))
                found.update(names)
        return found

    def cut_starts(self, text: str, least: int) -> Iterator[tuple[str, int]]:
        starts, firsts = self._starts_from(least)
        seen: set[str] = set()
        for at in range(max(0, len(text) - self.longest + 1), len(text) - least + 1):
            if text[at : at + least] not in firsts:
                continue
            tail = text[at:]
            k = bisect_left(starts, (tail,))
            while k < len(starts) and starts[k][0].startswith(tail):
                string, piece = starts[k]
                k += 1
                self.work.spend(1)
                if len(string) <= len(tail):
                    continue
                names = self._named().named(string) if piece else (string,)
                self.work.spend(len(names))
                for name in names:
                    if name not in seen:
                        seen.add(name)
                        yield name, len(tail)

    def _starts_from(self, least: int) -> tuple[list[tuple[str, bool]], set[str]]:
        if least not in self._starts:
            starts = [(value, False) for value in self.values if len(value) > least]
            starts += [(piece, True) for piece in self._owners if len(piece) > least]
            self.work.spend(len(starts))
            starts.sort()
            self._starts[least] = starts, {string[:least] for string, _ in starts}
        return self._starts[least]


Cover = tuple[list[int], list[int]]


def _cover(spans: Iterable[tuple[int, int]]) -> Cover:
    starts: list[int] = []
    ends: list[int] = []
    for start, end in sorted(spans):
        starts.append(start)
        ends.append(max(end, ends[-1]) if ends else end)
    return starts, ends


def _inside(cover: Cover | None, start: int, end: int) -> bool:
    if cover is None:
        return False
    starts, ends = cover
    at = bisect_right(starts, start) - 1
    return at >= 0 and ends[at] >= end


def _runs(
    on_line: Mapping[int, Mapping[str, Sequence[tuple[int, int]]]],
    seeds: Iterable[int],
    pieces: frozenset[str],
    cover: Cover | None,
    gap: int,
    work: MarkWork,
) -> list[tuple[int, int]]:
    def holds(line: int) -> bool:
        here = on_line.get(line)
        if not here:
            work.spend(1)
            return False
        few, many = (pieces, here) if len(pieces) <= len(here) else (here, pieces)
        work.spend(len(few))
        for piece in few:
            if piece in many and any(not _inside(cover, s, e) for s, e in here[piece]):
                return True
        return False

    runs: list[tuple[int, int]] = []
    for line in sorted(seeds):
        if runs and line <= runs[-1][1]:
            continue
        low = high = probe = line
        while (probe := probe + 1) - high <= gap:
            if holds(probe):
                high = probe
        probe = line
        while low - (probe := probe - 1) <= gap:
            if holds(probe):
                low = probe
        while runs and low <= runs[-1][1]:
            low = min(low, runs.pop()[0])
        runs.append((low, high))
    return runs


class _Forms:
    def __init__(
        self,
        pieces_of: Mapping[str, frozenset[str]],
        holders: Mapping[str, Sequence[str]],
        held: Mapping[str, set[str]],
        work: MarkWork,
    ) -> None:
        self._holders = holders
        self._work = work
        self._class: dict[str, int] = {}
        self._pieces: list[frozenset[str]] = []
        self._held: list[frozenset[str]] = []
        self._members: list[list[str]] = []
        classes: dict[tuple[frozenset[str], frozenset[str]], int] = {}
        for value, holding in held.items():
            holds = frozenset(holding)
            key = (pieces_of.get(value, holds), holds)
            number = classes.setdefault(key, len(self._pieces))
            if number == len(self._pieces):
                self._pieces.append(key[0])
                self._held.append(holds)
                self._members.append([])
            self._members[number].append(value)
            self._class[value] = number
        self._named: dict[str, tuple[str, ...]] = {}
        self._rarest: list[str | None] = [None] * len(self._pieces)
        self._checked: dict[tuple[int, int], bool] = {}

    def __repr__(self) -> str:
        return f"_Forms({len(self._class)} values)"

    def _within(self, one: int, other: int) -> bool:
        mine, theirs = self._pieces[one], self._held[other]
        self._work.spend(1)
        if len(mine) > len(theirs):
            return False
        rarest = self._rarest[one]
        if rarest is None:
            self._work.spend(len(mine))
            rarest = min(mine, key=lambda piece: (len(self._holders[piece]), piece))
            self._rarest[one] = rarest
        if rarest not in theirs:
            return False
        self._work.spend(len(mine))
        return mine <= theirs

    def _form(self, one: int, other: int) -> bool:
        pair = (one, other) if one < other else (other, one)
        answer = self._checked.get(pair)
        if answer is None:
            answer = self._within(one, other) or self._within(other, one)
            self._checked[pair] = answer
        else:
            self._work.spend(1)
        return answer

    def named(self, piece: str) -> tuple[str, ...]:
        if piece not in self._named:
            holders = self._holders[piece]
            self._work.spend(len(holders))
            holding = sorted({self._class[value] for value in holders})
            names: list[str] = []
            for number in holding:
                if all(other == number or self._form(number, other) for other in holding):
                    names += self._members[number]
            self._named[piece] = tuple(names)
        return self._named[piece]


class KnownIndex(ValueFinder):
    def __init__(self, known: Mapping[Subject, str]) -> None:
        super().__init__(known.values())


def known_in(
    session: Session, sealer: Sealer, repository_ids: Collection[int], *, opened: values.Opened
) -> dict[int, dict[Subject, str]]:
    wanted = sorted(set(repository_ids))
    here = Finding.repository_id.in_(wanted)
    counts = session.execute(
        select(
            func.count(distinct(Finding.secret_id)), func.count() - func.count(Finding.secret_id)
        )
        .where(here)
        .group_by(Finding.repository_id)
    ).all()
    if any(secrets + standalone > MAX_KNOWN_PER_REPO for secrets, standalone in counts):
        raise values.TooManyToDecrypt
    sizes = _sized(session, wanted)
    if any(size > MAX_KNOWN_BYTES for size in sizes.values()) or sum(sizes.values()) > (
        MAX_KNOWN_BYTES
    ):
        raise values.TooManyToDecrypt
    opened.reserve(sum(secrets + standalone for secrets, standalone in counts))
    held = opened.held
    found: dict[int, dict[Subject, str]] = {repository_id: {} for repository_id in wanted}
    sealed = (
        (
            SubjectKind.SECRET,
            Purpose.SECRET_VALUE,
            select(Finding.repository_id, Secret.id, Secret.value_sealed)
            .join(Secret, Secret.id == Finding.secret_id)
            .where(here)
            .distinct(),
        ),
        (
            SubjectKind.FINDING,
            Purpose.FINDING_MATCH,
            select(Finding.repository_id, Finding.id, Finding.match_sealed).where(
                here, Finding.secret_id.is_(None)
            ),
        ),
    )
    for kind, purpose, statement in sealed:
        for repository_id, subject_id, blob in session.execute(statement):
            subject = Subject(kind, subject_id)
            value = held.get(subject)
            if value is None:
                value = held[subject] = sealer.open(blob, purpose).decode("utf-8", "replace")
            found[repository_id][subject] = value
    return found


def _sized(session: Session, repository_ids: Sequence[int]) -> dict[int, int]:
    here = Finding.repository_id.in_(repository_ids)
    secrets = (
        select(
            Finding.repository_id.label("repository_id"),
            Secret.id.label("secret_id"),
            func.length(Secret.value_sealed).label("size"),
        )
        .join(Secret, Secret.id == Finding.secret_id)
        .where(here)
        .distinct()
        .subquery()
    )
    sizes: dict[int, int] = dict.fromkeys(repository_ids, 0)
    for repository_id, size in session.execute(
        select(secrets.c.repository_id, func.sum(secrets.c.size)).group_by(secrets.c.repository_id)
    ):
        sizes[repository_id] += int(size or 0)
    for repository_id, size in session.execute(
        select(Finding.repository_id, func.sum(func.length(Finding.match_sealed)))
        .where(here, Finding.secret_id.is_(None))
        .group_by(Finding.repository_id)
    ):
        sizes[repository_id] += int(size or 0)
    return sizes


def known_everywhere(
    session: Session, sealer: Sealer, *, opened: values.Opened
) -> dict[Subject, str]:
    standalone = Finding.secret_id.is_(None)
    count = (session.scalar(select(func.count()).select_from(Secret)) or 0) + (
        session.scalar(select(func.count()).select_from(Finding).where(standalone)) or 0
    )
    size = int(session.scalar(select(func.sum(func.length(Secret.value_sealed)))) or 0) + int(
        session.scalar(select(func.sum(func.length(Finding.match_sealed))).where(standalone)) or 0
    )
    if size > MAX_KNOWN_BYTES:
        raise values.TooManyToDecrypt
    held = opened.held
    opened.reserve(max(0, count - len(held)))
    found: dict[Subject, str] = {}
    sealed = (
        (SubjectKind.SECRET, Purpose.SECRET_VALUE, select(Secret.id, Secret.value_sealed)),
        (
            SubjectKind.FINDING,
            Purpose.FINDING_MATCH,
            select(Finding.id, Finding.match_sealed).where(standalone),
        ),
    )
    for kind, purpose, statement in sealed:
        for subject_id, blob in session.execute(statement):
            subject = Subject(kind, subject_id)
            value = held.get(subject)
            if value is None:
                opened.take(blob)
                value = held[subject] = sealer.open(blob, purpose).decode("utf-8", "replace")
            found[subject] = value
    return found


def known_values(
    session: Session, sealer: Sealer, repository_id: int, *, opened: values.Opened
) -> dict[Subject, str]:
    return known_in(session, sealer, [repository_id], opened=opened)[repository_id]
