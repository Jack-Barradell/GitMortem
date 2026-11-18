import string
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum

from sqlalchemy import BindParameter, bindparam, func, select
from sqlalchemy.orm import Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import Finding, MetaFrom, Secret
from gitmortem.triage.query import (
    LIST_MAX_PER_PAGE,
    Filters,
    ListPage,
    Order,
    View,
    clamped,
    matching_subjects,
    page_summary,
    rows_for,
)
from gitmortem.triage.subjects import NoSuchSubject, Subject, SubjectKind

MAX_VALUE_BYTES = 64 << 20
MIN_PARTIAL = 3
MAX_SEARCH_CHARS = 4096
MAX_DECRYPT = 500_000
MAX_HELD_BYTES = 256 << 20
MAX_MESSAGES_SEARCHED = 2_000_000


class ValueMode(StrEnum):
    EXACT = "exact"
    PARTIAL = "partial"
    TEXT = "text"
    HISTORY = "history"


VALUE_SEARCH_MODES = (ValueMode.EXACT, ValueMode.PARTIAL)


@dataclass(frozen=True)
class ValueSearch:
    text: str = field(repr=False)
    mode: ValueMode

    def __post_init__(self) -> None:
        if self.mode not in VALUE_SEARCH_MODES:
            raise ValueError("a value search is exact or partial")
        if not 1 <= len(self.text) <= MAX_SEARCH_CHARS:
            raise ValueError(f"a value search needs 1 to {MAX_SEARCH_CHARS} characters")
        if self.mode is ValueMode.PARTIAL and len(self.text) < MIN_PARTIAL:
            raise ValueError(f"a partial value search needs at least {MIN_PARTIAL} characters")


class TooManyToDecrypt(Exception):
    MESSAGE = "Too many values to open for one request: narrow the list with filters first."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class TooManyValueBytes(TooManyToDecrypt):
    MESSAGE = "These values are too large to send at once: ask for fewer of them."


class Opened:
    def __init__(self) -> None:
        self.limit = MAX_DECRYPT
        self.byte_limit = MAX_HELD_BYTES
        self.spent = 0
        self.bytes = 0
        self.held: dict[Subject, str] = {}

    def __len__(self) -> int:
        return len(self.held)

    def __repr__(self) -> str:
        return f"Opened({len(self.held)} of {self.limit})"

    def reserve(self, more: int) -> None:
        if self.spent + more > self.limit:
            raise TooManyToDecrypt
        self.spent += more

    def take(self, sealed: bytes) -> None:
        if self.bytes + len(sealed) > self.byte_limit:
            raise TooManyToDecrypt
        self.bytes += len(sealed)

    def give_back(self, sealed: bytes) -> None:
        self.bytes -= len(sealed)


def _request(opened: Opened | None) -> Opened:
    return Opened() if opened is None else opened


def _ids(name: str, ids: Collection[int]) -> BindParameter[int]:
    return bindparam(name, sorted(ids), expanding=True, literal_execute=True)


def _text(plain: bytes) -> str:
    return plain.decode("utf-8", "replace")


_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def search_messages(
    session: Session, sealer: Sealer, filters: Filters, *, opened: Opened | None = None
) -> Filters:
    if filters.canary and filters.canary_ids is None:
        from gitmortem.triage import canary

        chosen = canary.words(session, sealer)
        planted = canary.canary_finding_ids(session, sealer, chosen, opened=_request(opened))
        filters = replace(filters, canary_ids=planted)
    if not filters.text or filters.message_ids is not None:
        return filters
    request = _request(opened)
    held = Finding.message_sealed.is_not(None)
    count = session.scalar(select(func.count()).select_from(Finding).where(held)) or 0
    if count > MAX_MESSAGES_SEARCHED:
        raise TooManyToDecrypt
    needle = filters.text.translate(_ASCII_LOWER)
    found: set[int] = set()
    per_commit: dict[tuple[int, str], bool] = {}
    columns = (
        Finding.id,
        Finding.message_sealed,
        Finding.repository_id,
        Finding.commit,
        Finding.meta_from,
    )
    for finding_id, blob, repository_id, commit, meta_from in session.execute(
        select(*columns).where(held)
    ):
        if blob is None:
            continue
        key = (repository_id, commit) if meta_from is MetaFrom.COMMIT else None
        said = None if key is None else per_commit.get(key)
        if said is None:
            request.take(blob)
            said = needle in _text(sealer.open(blob, Purpose.FINDING_MESSAGE)).translate(
                _ASCII_LOWER
            )
            request.give_back(blob)
            if key is not None:
                per_commit[key] = said
        if said:
            found.add(finding_id)
    return replace(filters, message_ids=frozenset(found))


def _opened(
    session: Session, sealer: Sealer, subjects: Iterable[Subject], request: Opened
) -> dict[Subject, str]:
    held = request.held
    asked = list(subjects)
    new = [s for s in asked if s not in held] if held else asked
    request.reserve(len(new))
    secrets = {s.id for s in new if s.kind is SubjectKind.SECRET}
    findings = {s.id for s in new if s.kind is SubjectKind.FINDING}
    opened: dict[Subject, str] = {}
    if secrets:
        sealed = session.execute(
            select(Secret.id, Secret.value_sealed).where(Secret.id.in_(_ids("secrets", secrets)))
        )
        for secret_id, blob in sealed:
            request.take(blob)
            opened[Subject(SubjectKind.SECRET, secret_id)] = _text(
                sealer.open(blob, Purpose.SECRET_VALUE)
            )
    if findings:
        sealed = session.execute(
            select(Finding.id, Finding.match_sealed).where(
                Finding.id.in_(_ids("findings", findings)), Finding.secret_id.is_(None)
            )
        )
        for finding_id, blob in sealed:
            request.take(blob)
            opened[Subject(SubjectKind.FINDING, finding_id)] = _text(
                sealer.open(blob, Purpose.FINDING_MATCH)
            )
    for subject in new:
        if subject not in opened:
            raise NoSuchSubject(subject)
    held.update(opened)
    return opened if new is asked else {subject: held[subject] for subject in asked}


def values_of(
    session: Session,
    sealer: Sealer,
    subjects: Sequence[Subject],
    *,
    opened: Opened | None = None,
) -> dict[Subject, str]:
    found = _opened(session, sealer, subjects, _request(opened))
    size = 0
    for subject in subjects:
        size += len(found[subject].encode())
        if size > MAX_VALUE_BYTES:
            raise TooManyValueBytes
    return {subject: found[subject] for subject in subjects}


def value_of(session: Session, sealer: Sealer, subject: Subject) -> str:
    return values_of(session, sealer, [subject])[subject]


def search(
    session: Session, sealer: Sealer, query: ValueSearch, *, opened: Opened | None = None
) -> frozenset[Subject]:
    if query.mode is ValueMode.EXACT:
        found = session.scalar(
            select(Secret.id).where(Secret.value_hash == sealer.value_hash(query.text.encode()))
        )
        return frozenset() if found is None else frozenset({Subject(SubjectKind.SECRET, found)})
    request = _request(opened)
    standalone = Finding.secret_id.is_(None)
    count = (session.scalar(select(func.count()).select_from(Secret)) or 0) + (
        session.scalar(select(func.count()).select_from(Finding).where(standalone)) or 0
    )
    request.reserve(count - len(request))
    rows = (
        (SubjectKind.SECRET, Purpose.SECRET_VALUE, select(Secret.id, Secret.value_sealed)),
        (
            SubjectKind.FINDING,
            Purpose.FINDING_MATCH,
            select(Finding.id, Finding.match_sealed).where(standalone),
        ),
    )
    held = request.held
    matched: set[Subject] = set()
    for kind, purpose, statement in rows:
        for subject_id, blob in session.execute(statement):
            subject = Subject(kind, subject_id)
            value = held.get(subject)
            if value is not None:
                if query.text in value:
                    matched.add(subject)
                continue
            request.take(blob)
            value = _text(sealer.open(blob, purpose))
            if query.text in value:
                held[subject] = value
                matched.add(subject)
            else:
                request.give_back(blob)
    request.held = {subject: held[subject] for subject in matched}
    return frozenset(matched)


def sort_by_value(
    session: Session,
    sealer: Sealer,
    subjects: Collection[Subject],
    order: Order,
    *,
    opened: Opened | None = None,
) -> list[Subject]:
    found = _opened(session, sealer, subjects, _request(opened))
    return sorted(found, key=lambda subject: (found[subject], subject), reverse=order == "desc")


def value_page(
    session: Session,
    sealer: Sealer,
    filters: Filters,
    *,
    order: Order,
    page: int,
    per_page: int,
    only: Collection[Subject] | None = None,
    opened: Opened | None = None,
    summary: bool = True,
) -> ListPage:
    page, per_page = clamped(page, per_page, most=LIST_MAX_PER_PAGE)
    subjects = matching_subjects(session, filters, view=View.UNIQUE, only=only)
    ordered = sort_by_value(session, sealer, subjects, order, opened=opened)
    start = (page - 1) * per_page
    chosen = ordered[start : start + per_page]
    rows = rows_for(session, filters, view=View.UNIQUE, subjects=chosen)
    summarised = page_summary(session, filters, view=View.UNIQUE, only=only, summary=summary)
    return replace(summarised, rows=rows)
