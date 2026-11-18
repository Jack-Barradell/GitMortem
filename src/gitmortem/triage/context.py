import os
import re
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from sqlalchemy.orm import Session

from gitmortem.crypto import Sealer
from gitmortem.db.models import Finding
from gitmortem.explorer.access import (
    CONTEXT_WALK_SECONDS,
    RepoRead,
    Unavailable,
    checked_git_dir,
    git_read,
    holding_version,
    is_commit,
    open_for_read,
)
from gitmortem.gitread import BINARY_PROBE_BYTES, OBJECT_ID
from gitmortem.gitrun import GitError, GitOutputTooLarge, GitRunner, GitTimeout
from gitmortem.triage import values
from gitmortem.triage.detail import FindingView, NoSuchFinding, message_of
from gitmortem.triage.known_values import (
    MarkWork,
    Occurrence,
    TooMuchToMark,
    ValueFinder,
    known_in,
    known_values,
)
from gitmortem.triage.subjects import Subject, SubjectKind

__all__ = [
    "CONTEXT_GIT_SECONDS",
    "CONTEXT_WALK_SECONDS",
    "CUT_START_CHARS",
    "MAX_BLOB_BYTES",
    "MAX_LINE_CHARS",
    "MAX_TREE_LISTING",
    "WINDOW",
    "Context",
    "ContextLine",
    "ContextPlan",
    "MarkKind",
    "MarkedMessages",
    "Message",
    "NoSuchFinding",
    "Segment",
    "Unavailable",
    "batch_cap",
    "blob_at",
    "blob_bytes",
    "blob_size",
    "clean_file_text",
    "clean_line",
    "content_end",
    "mark_messages",
    "marked_spans",
    "marked_text",
    "plan_context",
    "read_blob",
    "read_context",
    "tree_at",
    "tree_listing",
    "window",
]

WINDOW = 3
MAX_BLOB_BYTES = 1 << 20
MAX_LINE_CHARS = 2000
CONTEXT_GIT_SECONDS = 20
MAX_TREE_LISTING = 64 << 20
CUT_START_CHARS = 4


def batch_cap(most: int) -> int:
    return len(b"%s blob %d\n" % (b"0" * 40, most)) + most + 1


_MAX_BATCH = batch_cap(MAX_BLOB_BYTES)
_REPLACED_BUT_LINE_BREAKS = (
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
)
_REPLACED = re.compile("[" + _REPLACED_BUT_LINE_BREAKS + "\n\r]")
_REPLACED_IN_FILES = re.compile("[" + _REPLACED_BUT_LINE_BREAKS + "]")


class MarkKind(StrEnum):
    OWN = "own"
    OTHER = "other"


@dataclass(frozen=True)
class Segment:
    text: str = field(repr=False)
    mark: MarkKind | None = None


@dataclass(frozen=True)
class ContextLine:
    number: int
    segments: tuple[Segment, ...]
    is_match: bool
    cut: bool


@dataclass(frozen=True)
class Context:
    lines: tuple[ContextLine, ...]
    integrity_failed: bool
    marks_dropped: bool = False


@dataclass(frozen=True)
class ContextPlan:
    repo: RepoRead
    commit: str
    path: bytes
    line: int
    own: tuple[str, ...] = field(repr=False)
    other: tuple[str, ...] = field(repr=False)
    marks_dropped: bool = False
    finder: ValueFinder = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "finder", ValueFinder((*self.own, *self.other)))


def plan_context(session: Session, sealer: Sealer, finding_id: int) -> ContextPlan | Unavailable:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NoSuchFinding(finding_id)
    repo = open_for_read(session, finding.repository_id)
    if isinstance(repo, Unavailable):
        return repo
    subject = (
        Subject(SubjectKind.FINDING, finding.id)
        if finding.secret_id is None
        else Subject(SubjectKind.SECRET, finding.secret_id)
    )
    try:
        known = known_values(session, sealer, finding.repository_id, opened=values.Opened())
        own = known[subject]
        other = set(known.values()) - {own, ""}
        return ContextPlan(
            repo=repo,
            commit=finding.commit,
            path=finding.path,
            line=finding.line,
            own=(own,),
            other=tuple(sorted(other)),
        )
    except values.TooManyToDecrypt:
        return ContextPlan(
            repo=repo,
            commit=finding.commit,
            path=finding.path,
            line=finding.line,
            own=(),
            other=(),
            marks_dropped=True,
        )


def _entry(listing: bytes, name: bytes) -> tuple[bytes, bytes] | None:
    at = 0
    while at <= len(listing):
        stop = listing.find(b"\0", at)
        stop = len(listing) if stop == -1 else stop
        tab = listing.find(b"\t", at, stop)
        if tab != -1 and stop - tab - 1 == len(name) and listing.startswith(name, tab + 1):
            parts = listing[at:tab].split(b" ")
            if len(parts) != 3 or OBJECT_ID.fullmatch(parts[2]) is None:
                raise GitError("ls-tree", 0, "git ls-tree printed an entry it should not")
            return parts[1], parts[2]
        at = stop + 1
    return None


def _blob_header(line: bytes, blob: bytes) -> int | None:
    parts = line.split(b" ")
    if len(parts) != 3 or parts[:2] != [blob, b"blob"] or not parts[2].isdigit():
        return None
    return int(parts[2])


def tree_listing(
    runner: GitRunner, git_dir: Path, tree: bytes, deadline: float, *, long: bool = False
) -> bytes:
    sizes = ["-l"] if long else []
    return git_read(
        runner,
        git_dir,
        ["ls-tree", "-z", *sizes, "--full-tree", "--end-of-options", tree.decode("ascii")],
        deadline,
        max_stdout=MAX_TREE_LISTING,
    )


def tree_at(
    runner: GitRunner, git_dir: Path, commit: str, names: Sequence[bytes], deadline: float
) -> bytes | None:
    tree = commit.encode("ascii")
    for name in names:
        entry = _entry(tree_listing(runner, git_dir, tree, deadline), name)
        if entry is None or entry[0] != b"tree":
            return None
        tree = entry[1]
    return tree


def blob_at(
    runner: GitRunner, git_dir: Path, commit: str, names: Sequence[bytes], deadline: float
) -> bytes | None:
    folder = tree_at(runner, git_dir, commit, names[:-1], deadline)
    if folder is None:
        return None
    entry = _entry(tree_listing(runner, git_dir, folder, deadline), names[-1])
    return entry[1] if entry is not None and entry[0] == b"blob" else None


def blob_size(runner: GitRunner, git_dir: Path, blob: bytes, deadline: float) -> int | None:
    checked = git_read(runner, git_dir, ["cat-file", "--batch-check"], deadline, stdin=blob + b"\n")
    return _blob_header(checked.rstrip(b"\n"), blob)


def blob_bytes(
    runner: GitRunner, git_dir: Path, blob: bytes, deadline: float, *, most: int
) -> bytes | Unavailable:
    out = git_read(
        runner,
        git_dir,
        ["cat-file", "--batch"],
        deadline,
        stdin=blob + b"\n",
        max_stdout=batch_cap(most),
    )
    header, _, rest = out.partition(b"\n")
    size = _blob_header(header, blob)
    if size is None:
        return Unavailable.UNREADABLE
    if size > most:
        return Unavailable.TOO_LARGE
    if len(rest) != size + 1 or rest[size:] != b"\n":
        raise GitError("cat-file", 0, "git cat-file did not give the whole blob")
    return rest[:size]


def read_blob(
    runner: GitRunner, git_dir: Path, commit: str, path: bytes, *, timeout: float
) -> bytes | Unavailable:
    names = path.split(b"/")
    if not all(names):
        return Unavailable.NOT_IN_HISTORY
    deadline = time.monotonic() + timeout
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        blob = blob_at(runner, git_dir, commit, names, deadline)
        if blob is None:
            return Unavailable.NOT_IN_HISTORY
        size = blob_size(runner, git_dir, blob, deadline)
        if size is None:
            return Unavailable.UNREADABLE
        if size > MAX_BLOB_BYTES:
            return Unavailable.TOO_LARGE
        try:
            return blob_bytes(runner, git_dir, blob, deadline, most=MAX_BLOB_BYTES)
        except GitOutputTooLarge:
            return Unavailable.TOO_LARGE
    except GitTimeout:
        return Unavailable.TIMED_OUT


def read_context(
    runner: GitRunner,
    plan: ContextPlan,
    *,
    bases: Collection[Path],
    data_dir: Path,
    key_file: Path | None,
    timeout: float,
) -> Context | Unavailable:
    deadline = time.monotonic() + timeout
    if len(plan.repo.versions) > 1:
        git_dir = holding_version(
            runner,
            plan.repo,
            plan.commit,
            bases=bases,
            data_dir=data_dir,
            key_file=key_file,
            deadline=deadline,
        )
    else:
        git_dir = checked_git_dir(
            runner, plan.repo, bases=bases, data_dir=data_dir, key_file=key_file, deadline=deadline
        )
    if isinstance(git_dir, Unavailable):
        return git_dir
    try:
        blob = read_blob(
            runner, git_dir, plan.commit, plan.path, timeout=deadline - time.monotonic()
        )
    except GitError:
        gone = not os.path.lexists(plan.repo.git_dir)
        return Unavailable.REPOSITORY_GONE if gone else Unavailable.REFUSED
    if isinstance(blob, Unavailable):
        return blob
    if b"\0" in blob[:BINARY_PROBE_BYTES]:
        return Unavailable.BINARY
    dropped = plan.marks_dropped
    try:
        lines = _window(blob, plan.line, plan.finder, own=plan.own)
    except TooMuchToMark:
        lines, dropped = _window(blob, plan.line, ValueFinder(()), own=()), True
    return Context(lines=lines, integrity_failed=plan.repo.integrity_failed, marks_dropped=dropped)


def _spans(text: str, first: int, last: int) -> list[tuple[int, int, int]]:
    spans = []
    start, number = 0, 1
    while number <= last and start < len(text):
        end = text.find("\n", start)
        stop = len(text) if end == -1 else end
        if number >= first:
            spans.append((number, start, stop))
        if end == -1:
            break
        start, number = end + 1, number + 1
    return spans


def _found(
    text: str, lo: int, hi: int, finder: ValueFinder, *, cut: bool = False
) -> list[Occurrence]:
    if not finder.values:
        return []
    reach = finder.longest - 1
    start, stop = max(0, lo - reach), min(len(text), hi + reach)
    found = [(start + b, start + e, v) for b, e, v in finder.occurrences(text[start:stop])]
    if cut:
        body = text[:-1] if text.endswith("\ufffd") else text
        for value, size in finder.cut_starts(body, CUT_START_CHARS):
            found.append((len(body) - size, len(text), value))
    return found


def _merged(
    found: Collection[tuple[int, int, str]], own: Collection[str]
) -> list[tuple[int, int, MarkKind]]:
    kinds = sorted(
        (begin, end, MarkKind.OWN if value in own else MarkKind.OTHER)
        for begin, end, value in found
    )
    merged: list[tuple[int, int, MarkKind]] = []
    for begin, end, kind in kinds:
        if merged and begin < merged[-1][1]:
            was_begin, was_end, was_kind = merged[-1]
            own_in = MarkKind.OWN in (was_kind, kind)
            merged[-1] = (was_begin, max(was_end, end), MarkKind.OWN if own_in else MarkKind.OTHER)
        else:
            merged.append((begin, end, kind))
    return merged


def _marks(
    text: str, lo: int, hi: int, finder: ValueFinder, own: Collection[str]
) -> list[tuple[int, int, MarkKind]]:
    return _merged(_found(text, lo, hi, finder), set(own))


def masked(text: str, finder: ValueFinder, marker: str, *, cut: bool = False) -> str:
    if not text or not finder.values:
        return text
    out: list[str] = []
    at = 0
    for begin, end, _ in _merged(_found(text, 0, len(text), finder, cut=cut), ()):
        out.append(text[at:begin])
        out.append(marker)
        at = end
    out.append(text[at:])
    return "".join(out)


def clean_line(text: str) -> str:
    return _REPLACED.sub("\ufffd", text)


def clean_file_text(text: str) -> str:
    return _REPLACED_IN_FILES.sub("\ufffd", text)


def content_end(text: str, start: int, end: int) -> int:
    return end - 1 if end > start and text[end - 1] == "\r" else end


def _segments(
    text: str, start: int, stop: int, marks: Sequence[tuple[int, int, MarkKind]]
) -> tuple[Segment, ...]:
    segments: list[Segment] = []
    at = start
    for begin, finish, kind in marks:
        if finish <= start or begin >= stop:
            continue
        begin = max(begin, at)
        if begin > at:
            segments.append(Segment(clean_line(text[at:begin])))
        at = min(finish, stop)
        segments.append(Segment(clean_line(text[begin:at]), kind))
    if at < stop:
        segments.append(Segment(clean_line(text[at:stop])))
    return tuple(segments)


def _line(
    text: str,
    number: int,
    start: int,
    end: int,
    marks: Sequence[tuple[int, int, MarkKind]],
    is_match: bool,
) -> ContextLine:
    end = content_end(text, start, end)
    cut = end - start > MAX_LINE_CHARS
    stop = start + MAX_LINE_CHARS if cut else end
    return ContextLine(
        number=number, segments=_segments(text, start, stop, marks), is_match=is_match, cut=cut
    )


def window(
    blob: bytes, line: int, *, own: Sequence[str], other: Sequence[str]
) -> tuple[ContextLine, ...]:
    return _window(blob, line, ValueFinder((*own, *other)), own=own)


def _window(
    blob: bytes, line: int, finder: ValueFinder, *, own: Collection[str]
) -> tuple[ContextLine, ...]:
    text = blob.decode("utf-8", "replace")
    spans = _spans(text, line - WINDOW, line + WINDOW)
    if not spans:
        return ()
    marks = _marks(text, spans[0][1], spans[-1][2], finder, own)
    return tuple(
        _line(text, number, start, end, marks, number == line) for number, start, end in spans
    )


def _message_lines(
    text: str, marks: Sequence[tuple[int, int, MarkKind]], stop: int | None = None
) -> tuple[tuple[Segment, ...], ...]:
    shown = len(text) if stop is None else min(stop, len(text))
    spans = _spans(text, 1, text.count("\n", 0, shown) + 1)
    return tuple(
        _segments(text, start, min(content_end(text, start, end), shown), marks)
        for _, start, end in spans
        if start < shown
    )


def marked_text(
    text: str,
    *,
    own: Sequence[str],
    other: Sequence[str],
    stop: int | None = None,
    cut: bool = False,
) -> tuple[tuple[Segment, ...], ...]:
    found = _found(text, 0, len(text), ValueFinder((*own, *other)), cut=cut)
    return marked_spans(text, found, own=own, stop=stop)


def marked_spans(
    text: str,
    found: Collection[Occurrence],
    *,
    own: Collection[str] = (),
    stop: int | None = None,
) -> tuple[tuple[Segment, ...], ...]:
    return _message_lines(text, _merged(found, set(own)), stop)


@dataclass(frozen=True)
class Message:
    lines: tuple[tuple[Segment, ...], ...]

    @property
    def subject(self) -> tuple[Segment, ...]:
        return self.lines[0] if self.lines else ()


@dataclass(frozen=True)
class MarkedMessages:
    messages: list[Message | None]
    marks_dropped: bool


def mark_messages(session: Session, sealer: Sealer, views: Sequence[FindingView]) -> MarkedMessages:
    try:
        return MarkedMessages(_marked_messages(session, sealer, views), marks_dropped=False)
    except values.TooManyToDecrypt:
        opened = [message_of(sealer, view) for view in views]
        plain = [None if text is None else Message(marked_spans(text, ())) for text in opened]
        return MarkedMessages(plain, marks_dropped=True)


def _marked_messages(
    session: Session,
    sealer: Sealer,
    views: Sequence[FindingView],
    *,
    work: MarkWork | None = None,
) -> list[Message | None]:
    repositories = {v.repository_id for v in views if v.message_sealed is not None}
    if not repositories:
        return [None] * len(views)
    known = known_in(session, sealer, repositories, opened=values.Opened())
    work = MarkWork() if work is None else work
    finders = {
        repository_id: ValueFinder(held.values(), work=work)
        for repository_id, held in known.items()
    }
    searched: dict[tuple[int, str, bool], list[Occurrence]] = {}
    marked: dict[tuple[int, Subject, str, bool], Message] = {}
    found: list[Message | None] = []
    for view in views:
        message = message_of(sealer, view)
        if message is None:
            found.append(None)
            continue
        repository_id = view.repository_id
        subject = (
            Subject(SubjectKind.FINDING, view.id)
            if view.secret_id is None
            else Subject(SubjectKind.SECRET, view.secret_id)
        )
        key = (repository_id, subject, message, view.message_cut)
        if key not in marked:
            text = (repository_id, message, view.message_cut)
            if text not in searched:
                searched[text] = _found(
                    message, 0, len(message), finders[repository_id], cut=view.message_cut
                )
            own = (known[repository_id][subject],)
            marked[key] = Message(marked_spans(message, searched[text], own=own))
        found.append(marked[key])
    return found
