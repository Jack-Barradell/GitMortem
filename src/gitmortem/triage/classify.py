import uuid
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import datetime

from sqlalchemy import (
    BindParameter,
    ColumnElement,
    and_,
    bindparam,
    distinct,
    func,
    insert,
    not_,
    or_,
    select,
    union_all,
    update,
)
from sqlalchemy.orm import InstrumentedAttribute, Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import (
    Finding,
    Note,
    Scan,
    ScanState,
    Secret,
    SecretStatus,
    StatusChange,
    User,
)
from gitmortem.triage.notes import clean_text
from gitmortem.triage.query import (
    ENDED_SCAN,
    Bound,
    Filters,
    View,
    matching_subjects,
    names_reported,
    reported_mark,
)
from gitmortem.triage.subjects import NoSuchSubject, Subject, SubjectKind, columns, require

MAX_SUBJECTS = 100_000
NOTE_BYTES_PER_CHANGE = 16 * 1024 * 1024
NOTE_CHUNK = 1_000


class TooManySubjects(ValueError):
    MESSAGE = (
        f"A status change may touch at most {MAX_SUBJECTS} subjects: narrow the list with "
        "filters first."
    )

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class NoteTooLarge(ValueError):
    MESSAGE = (
        "A note is copied onto every subject a change moves, and this one would come to more "
        f"than {NOTE_BYTES_PER_CHANGE // (1024 * 1024)} MiB: shorten it, or change fewer "
        "subjects at once."
    )

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class ScanNotEnded(ValueError):
    QUEUED = "That scan has not started yet: select rows instead, or wait for it to end."
    RUNNING = "That scan is still running: select rows instead, or wait for it to end."
    MISSING = "No such scan: select rows instead."
    STALE = "That scan had not ended when this page loaded: reload the list, then select again."

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ReportedMoved(ValueError):
    REASON = "reported_moved"
    MESSAGE = (
        "What is still reported has changed since this page loaded: a scan, an import or a "
        "re-read recorded findings, or an import was removed. Read the list again, then select "
        "again."
    )

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class SpansRepositories(ValueError):
    REASON = "spans_repositories"

    def __init__(self, repositories: int) -> None:
        self.repositories = repositories
        super().__init__(
            f"This change applies to a secret found in {repositories} repositories: confirm it"
            " applies to all of them."
        )


def widest_reach(session: Session, subjects: Sequence[Subject]) -> int:
    secrets = [subject.id for subject in subjects if subject.kind is SubjectKind.SECRET]
    widest = 1 if len(secrets) < len(subjects) else 0
    for start in range(0, len(secrets), NOTE_CHUNK):
        held = _ids("reach", secrets[start : start + NOTE_CHUNK])
        counted = (
            select(func.count(distinct(Finding.repository_id)).label("reach"))
            .where(Finding.secret_id.in_(held))
            .group_by(Finding.secret_id)
            .subquery()
        )
        widest = max(widest, session.scalar(select(func.max(counted.c.reach))) or 0)
    return widest


@dataclass(frozen=True)
class Skipped:
    subject: Subject
    status: SecretStatus
    changed_by: str | None
    changed_at: datetime


@dataclass(frozen=True)
class StatusResult:
    batch_id: str
    changed: int
    unchanged: int
    skipped: list[Skipped]
    moved: list[Subject]


@dataclass(frozen=True)
class HistoryEntry:
    at: datetime
    user: str | None
    from_status: SecretStatus
    to_status: SecretStatus
    batch_id: str


def _ids(name: str, ids: Collection[int]) -> BindParameter[int]:
    return bindparam(name, sorted(ids), expanding=True, literal_execute=True)


def _split(subjects: Collection[Subject]) -> tuple[set[int], set[int]]:
    return (
        {s.id for s in subjects if s.kind is SubjectKind.SECRET},
        {s.id for s in subjects if s.kind is SubjectKind.FINDING},
    )


def _current(session: Session, subjects: Sequence[Subject]) -> dict[Subject, SecretStatus]:
    secrets, findings = _split(subjects)
    current: dict[Subject, SecretStatus] = {}
    if secrets:
        for secret_id, status in session.execute(
            select(Secret.id, Secret.status).where(Secret.id.in_(_ids("secrets", secrets)))
        ):
            current[Subject(SubjectKind.SECRET, secret_id)] = status
    if findings:
        for finding_id, own in session.execute(
            select(Finding.id, Finding.status).where(
                Finding.id.in_(_ids("findings", findings)), Finding.secret_id.is_(None)
            )
        ):
            current[Subject(SubjectKind.FINDING, finding_id)] = own or SecretStatus.UNCLASSIFIED
    for subject in subjects:
        if subject not in current:
            raise NoSuchSubject(subject)
    return current


def described(
    session: Session, subjects: Collection[Subject]
) -> dict[Subject, tuple[str, SecretStatus]]:
    secrets, findings = _split(subjects)
    found: dict[Subject, tuple[str, SecretStatus]] = {}
    if secrets:
        for secret_id, kind, status in session.execute(
            select(Secret.id, Secret.kind, Secret.status).where(
                Secret.id.in_(_ids("secrets", secrets))
            )
        ):
            found[Subject(SubjectKind.SECRET, secret_id)] = (kind, status)
    if findings:
        for finding_id, rule, own in session.execute(
            select(Finding.id, Finding.rule, Finding.status).where(
                Finding.id.in_(_ids("findings", findings)), Finding.secret_id.is_(None)
            )
        ):
            found[Subject(SubjectKind.FINDING, finding_id)] = (
                rule,
                own or SecretStatus.UNCLASSIFIED,
            )
    return found


def _changed_since(
    session: Session,
    subjects: Collection[Subject],
    seen_change_id: int,
    *,
    own_batches: Collection[str] = (),
    user_id: int | None = None,
) -> dict[Subject, Skipped]:
    secrets, findings = _split(subjects)
    passed_over: list[ColumnElement[bool]] = []
    if own_batches and user_id is not None:
        mine = and_(StatusChange.batch_id.in_(list(own_batches)), StatusChange.user_id == user_id)
        passed_over.append(not_(mine))
    found = session.execute(
        select(
            func.coalesce(StatusChange.secret_id, -StatusChange.finding_id),
            StatusChange.to_status,
            User.username,
            StatusChange.at,
        )
        .outerjoin(User, User.id == StatusChange.user_id)
        .where(
            StatusChange.id > seen_change_id,
            or_(
                StatusChange.secret_id.in_(_ids("changed_secrets", secrets)),
                StatusChange.finding_id.in_(_ids("changed_findings", findings)),
            ),
            *passed_over,
        )
        .order_by(StatusChange.id)
    )
    latest: dict[Subject, Skipped] = {}
    for key, status, username, at in found:
        if key > 0:
            subject = Subject(SubjectKind.SECRET, key)
        else:
            subject = Subject(SubjectKind.FINDING, -key)
        latest[subject] = Skipped(subject, status, username, at)
    return latest


def _status_then(
    session: Session, subjects: Collection[Subject], filters: Filters, seen_change_id: int
) -> set[Subject]:
    secrets, findings = _split(subjects)

    def then(
        column: InstrumentedAttribute[int | None], subject_id: InstrumentedAttribute[int]
    ) -> ColumnElement[SecretStatus]:
        return (
            select(StatusChange.from_status)
            .where(column == subject_id, StatusChange.id > seen_change_id)
            .order_by(StatusChange.id)
            .limit(1)
            .scalar_subquery()
        )

    def kept(status: ColumnElement[SecretStatus]) -> ColumnElement[bool]:
        chosen = status.in_(filters.statuses)
        return ~chosen if filters.statuses_negated else chosen

    secret_then = func.coalesce(then(StatusChange.secret_id, Secret.id), Secret.status)
    finding_then = func.coalesce(then(StatusChange.finding_id, Finding.id), Finding.status)
    found = session.scalars(
        union_all(
            select(Secret.id).where(
                Secret.id.in_(_ids("then_secrets", secrets)), kept(secret_then)
            ),
            select(-Finding.id).where(
                Finding.id.in_(_ids("then_findings", findings)),
                Finding.secret_id.is_(None),
                kept(finding_then),
            ),
        )
    )
    return {
        Subject(SubjectKind.SECRET, key) if key > 0 else Subject(SubjectKind.FINDING, -key)
        for key in found
    }


def refuse_unended_scan(session: Session, filters: Filters, bound: Bound) -> None:
    if filters.scan_id is None:
        return
    state = session.scalar(select(Scan.state).where(Scan.id == filters.scan_id))
    if state is None:
        raise ScanNotEnded(ScanNotEnded.MISSING)
    if state is ScanState.QUEUED:
        raise ScanNotEnded(ScanNotEnded.QUEUED)
    if state not in ENDED_SCAN:
        raise ScanNotEnded(ScanNotEnded.RUNNING)
    if bound.scan_ended is not True:
        raise ScanNotEnded(ScanNotEnded.STALE)


def refuse_moved_report(session: Session, filters: Filters, bound: Bound) -> None:
    if not names_reported(filters):
        return
    if bound.reported_mark is None or bound.reported_mark != reported_mark(session):
        raise ReportedMoved


def matching_as_seen(
    session: Session,
    filters: Filters,
    *,
    view: View,
    bound: Bound,
    only: Collection[Subject] | None,
    seen_change_id: int,
) -> list[Subject]:
    refuse_unended_scan(session, filters, bound)
    refuse_moved_report(session, filters, bound)
    unfiltered = replace(filters, statuses=(), statuses_negated=False)
    candidates = matching_subjects(session, unfiltered, view=view, bound=bound, only=only)
    if not filters.statuses or not candidates:
        return candidates
    kept = _status_then(session, candidates, filters, seen_change_id)
    return [subject for subject in candidates if subject in kept]


def set_status(
    session: Session,
    subjects: Sequence[Subject],
    status: SecretStatus,
    *,
    user: User,
    seen_change_id: int,
    note: str | None,
    sealer: Sealer,
    now: datetime,
    across_repositories: int | None,
    own_batches: Collection[str] = (),
) -> StatusResult:
    asked = list(dict.fromkeys(subjects))
    if len(asked) > MAX_SUBJECTS:
        raise TooManySubjects
    plain = None if note is None else clean_text(note).encode()
    current = _current(session, asked)
    since = _changed_since(session, asked, seen_change_id, own_batches=own_batches, user_id=user.id)
    skipped = [since[subject] for subject in asked if subject in since]
    moving = [s for s in asked if s not in since and current[s] is not status]
    if plain is not None and len(plain) * len(moving) > NOTE_BYTES_PER_CHANGE:
        raise NoteTooLarge
    reach = widest_reach(session, moving)
    if reach > 1 and (across_repositories is None or across_repositories < reach):
        raise SpansRepositories(reach)
    batch_id = uuid.uuid4().hex
    if moving:
        session.execute(
            insert(StatusChange),
            [
                {
                    **columns(subject),
                    "from_status": current[subject],
                    "to_status": status,
                    "user_id": user.id,
                    "at": now,
                    "batch_id": batch_id,
                }
                for subject in moving
            ],
        )
        secrets, findings = _split(moving)
        if secrets:
            session.execute(
                update(Secret)
                .where(Secret.id.in_(_ids("moved_secrets", secrets)))
                .values(status=status)
            )
        if findings:
            session.execute(
                update(Finding)
                .where(Finding.id.in_(_ids("moved_findings", findings)))
                .values(status=status)
            )
        if plain is not None:
            for start in range(0, len(moving), NOTE_CHUNK):
                session.execute(
                    insert(Note),
                    [
                        {
                            **columns(subject),
                            "author_user_id": user.id,
                            "created_at": now,
                            "text_sealed": sealer.seal(plain, Purpose.NOTE_TEXT),
                        }
                        for subject in moving[start : start + NOTE_CHUNK]
                    ],
                )
    return StatusResult(
        batch_id=batch_id,
        changed=len(moving),
        unchanged=len(asked) - len(moving) - len(skipped),
        skipped=skipped,
        moved=moving,
    )


def history(session: Session, subject: Subject) -> list[HistoryEntry]:
    require(session, subject)
    on = StatusChange.secret_id if subject.kind is SubjectKind.SECRET else StatusChange.finding_id
    found = session.execute(
        select(
            StatusChange.at,
            User.username,
            StatusChange.from_status,
            StatusChange.to_status,
            StatusChange.batch_id,
        )
        .outerjoin(User, User.id == StatusChange.user_id)
        .where(on == subject.id)
        .order_by(StatusChange.id.desc())
    )
    return [
        HistoryEntry(at=at, user=username, from_status=old, to_status=new, batch_id=batch)
        for at, username, old, new, batch in found
    ]
