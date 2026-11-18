import json
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, func, or_, select, true
from sqlalchemy.orm import Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import Finding, InstanceSetting
from gitmortem.scanning.settings import INSTANCE_SETTINGS_ID
from gitmortem.triage import values
from gitmortem.triage.subjects import Subject, SubjectKind

__all__ = [
    "BUILT_IN_WORDS",
    "MAX_CHEAP_FINDINGS",
    "MAX_CHECKED_FINDINGS",
    "MAX_HINTS_SHOWN",
    "MAX_OWN_WORDS",
    "MAX_WORD_CHARS",
    "MIN_WORD_CHARS",
    "CanaryField",
    "Hint",
    "TooManyToCheck",
    "canary_finding_ids",
    "canary_subjects",
    "findings_behind",
    "hints_of",
    "own_words",
    "set_own_words",
    "words",
]

BUILT_IN_WORDS = (
    "canary",
    "canarytoken",
    "honeytoken",
    "honey token",
    "honeypot",
    "decoy",
    "tripwire",
)
MAX_OWN_WORDS = 100
MIN_WORD_CHARS = 3
MAX_WORD_CHARS = 64
MAX_HINTS_SHOWN = 20
MAX_CHEAP_FINDINGS = 2_000
MAX_CHECKED_FINDINGS = 100_000


class TooManyToCheck(Exception):
    pass


class CanaryField(StrEnum):
    MESSAGE = "message"
    PATH = "path"
    LINE = "line"
    AUTHOR = "author"


@dataclass(frozen=True)
class Hint:
    finding_id: int
    field: CanaryField
    word: str


def _settings(session: Session) -> InstanceSetting:
    row = session.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    if row is None:
        row = InstanceSetting(id=INSTANCE_SETTINGS_ID)
        session.add(row)
    return row


def own_words(session: Session, sealer: Sealer) -> tuple[str, ...]:
    row = session.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    if row is None or row.canary_words_sealed is None:
        return ()
    found = json.loads(sealer.open(row.canary_words_sealed, Purpose.CANARY_WORDS))
    return tuple(word for word in found if isinstance(word, str))


def set_own_words(session: Session, sealer: Sealer, given: Sequence[str]) -> tuple[int, int] | None:
    chosen = list(dict.fromkeys(word.strip().casefold() for word in given if word.strip()))
    if len(chosen) > MAX_OWN_WORDS:
        raise ValueError(f"at most {MAX_OWN_WORDS} words")
    if any(not MIN_WORD_CHARS <= len(word) <= MAX_WORD_CHARS for word in chosen):
        raise ValueError(f"a word is {MIN_WORD_CHARS} to {MAX_WORD_CHARS} characters")
    before = own_words(session, sealer)
    if list(before) == chosen:
        return None
    row = _settings(session)
    row.canary_words_sealed = (
        sealer.seal(json.dumps(chosen).encode(), Purpose.CANARY_WORDS) if chosen else None
    )
    session.flush()
    return len(before), len(chosen)


def words(session: Session, sealer: Sealer) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*BUILT_IN_WORDS, *own_words(session, sealer))))


def _word_in(text: str, chosen: Sequence[str]) -> str | None:
    folded = text.casefold()
    return next((word for word in chosen if word in folded), None)


_COLUMNS = (
    Finding.id,
    Finding.repository_id,
    Finding.commit,
    Finding.display_path,
    Finding.author_name,
    Finding.author_email,
    Finding.message_sealed,
    Finding.match_sealed,
)


class _Reader:
    def __init__(
        self,
        sealer: Sealer,
        chosen: Sequence[str],
        opened: values.Opened,
        lines: Mapping[int, str] | None = None,
    ) -> None:
        self.sealer = sealer
        self.chosen = chosen
        self.opened = opened
        self.lines = lines or {}
        self.messages: dict[tuple[int, str], str | None] = {}

    def _open(self, blob: bytes, purpose: Purpose) -> str:
        self.opened.take(blob)
        text = self.sealer.open(blob, purpose).decode("utf-8", "replace")
        self.opened.give_back(blob)
        return text

    def _message(self, repository_id: int, commit: str, blob: bytes | None) -> str | None:
        key = (repository_id, commit)
        if key not in self.messages:
            self.messages[key] = (
                None
                if blob is None
                else _word_in(self._open(blob, Purpose.FINDING_MESSAGE), self.chosen)
            )
        return self.messages[key]

    def hints(self, row: Any) -> Iterator[Hint]:
        finding_id, repository_id, commit, path, name, email, message, line = row
        if (word := self._message(repository_id, commit, message)) is not None:
            yield Hint(finding_id, CanaryField.MESSAGE, word)
        if (word := _word_in(path, self.chosen)) is not None:
            yield Hint(finding_id, CanaryField.PATH, word)
        text = self.lines.get(finding_id)
        if text is None:
            text = self._open(line, Purpose.FINDING_MATCH)
        if (word := _word_in(text, self.chosen)) is not None:
            yield Hint(finding_id, CanaryField.LINE, word)
        if (word := _word_in(f"{name} {email}", self.chosen)) is not None:
            yield Hint(finding_id, CanaryField.AUTHOR, word)


def _of_subjects(subjects: Collection[Subject]) -> ColumnElement[bool]:
    secrets = sorted(s.id for s in subjects if s.kind is SubjectKind.SECRET)
    findings = sorted(s.id for s in subjects if s.kind is SubjectKind.FINDING)
    return or_(
        Finding.secret_id.in_(secrets),
        Finding.id.in_(findings) & Finding.secret_id.is_(None),
    )


def _count(session: Session, where: ColumnElement[bool]) -> int:
    return session.scalar(select(func.count()).select_from(Finding).where(where)) or 0


def findings_behind(session: Session, subjects: Iterable[Subject]) -> int:
    asked = set(subjects)
    return _count(session, _of_subjects(asked)) if asked else 0


def hints_of(
    session: Session,
    sealer: Sealer,
    subject: Subject,
    chosen: Sequence[str],
    *,
    opened: values.Opened,
    most: int = MAX_CHECKED_FINDINGS,
) -> tuple[list[Hint], bool]:
    where = _of_subjects([subject])
    if _count(session, where) > most:
        raise TooManyToCheck
    query = select(*_COLUMNS).where(where).order_by(Finding.id)
    reader = _Reader(sealer, chosen, opened)
    found: list[Hint] = []
    for row in session.execute(query):
        for hint in reader.hints(row):
            if len(found) == MAX_HINTS_SHOWN:
                return found, True
            found.append(hint)
    return found, False


def canary_subjects(
    session: Session,
    sealer: Sealer,
    subjects: Iterable[Subject],
    chosen: Sequence[str],
    *,
    opened: values.Opened,
    shown: Mapping[Subject, str] | None = None,
    most: int = MAX_CHECKED_FINDINGS,
) -> set[Subject]:
    asked = set(subjects)
    if not asked:
        return set()
    where = _of_subjects(asked)
    if _count(session, where) > most:
        raise TooManyToCheck
    query = select(*_COLUMNS, Finding.secret_id).where(where).order_by(Finding.id)
    lines = {
        subject.id: text
        for subject, text in (shown or {}).items()
        if subject.kind is SubjectKind.FINDING
    }
    reader = _Reader(sealer, chosen, opened, lines)
    found: set[Subject] = set()
    for row in session.execute(query):
        subject = (
            Subject(SubjectKind.SECRET, row.secret_id)
            if row.secret_id is not None
            else Subject(SubjectKind.FINDING, row.id)
        )
        if subject in found:
            continue
        if next(reader.hints(row[:-1]), None) is not None:
            found.add(subject)
    return found


def canary_finding_ids(
    session: Session, sealer: Sealer, chosen: Sequence[str], *, opened: values.Opened
) -> frozenset[int]:
    if _count(session, true()) > values.MAX_MESSAGES_SEARCHED:
        raise values.TooManyToDecrypt
    query = select(*_COLUMNS).order_by(Finding.id)
    reader = _Reader(sealer, chosen, opened)
    return frozenset(row.id for row in session.execute(query) if next(reader.hints(row), None))
