from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.orm import Session

from gitmortem.db.models import AuditEvent, AuditSubject, AuditValue, User, utcnow
from gitmortem.triage.subjects import Subject, SubjectKind, columns

MAX_DETAIL_VALUE_LENGTH = 256
NAME_SUBJECTS_UP_TO = 200
MAX_PER_PAGE = 200
MAX_PAGE = 1_000_000_000
CLEAR_BATCH = 5_000

FORBIDDEN_DETAIL_KEYS = frozenset(
    {"password", "new_password", "current_password", "password_hash", "secret", "token", "key"}
)


class AuditAction(StrEnum):
    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    LOGIN_LOCKED = "login_locked"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105
    PASSWORD_RESET = "password_reset"  # noqa: S105
    USER_CREATED = "user_created"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    ADMIN_BOOTSTRAPPED = "admin_bootstrapped"
    SCAN_ROOT_ADDED = "scan_root_added"
    SCAN_ROOT_REMOVED = "scan_root_removed"
    TOOL_SETTINGS_CHANGED = "tool_settings_changed"
    SCAN_SETTINGS_CHANGED = "scan_settings_changed"
    UPLOAD_LIMITS_CHANGED = "upload_limits_changed"
    CANARY_WORDS_CHANGED = "canary_words_changed"
    SCAN_STARTED = "scan_started"
    SCAN_CANCELLED = "scan_cancelled"
    SCAN_REREAD = "scan_reread"
    DISCOVERY_STARTED = "discovery_started"
    DISCOVERY_CANCELLED = "discovery_cancelled"
    SECRET_REVEALED = "secret_revealed"  # noqa: S105
    SECRET_COPIED = "secret_copied"  # noqa: S105
    VALUES_SHOWN = "values_shown"
    VALUE_SEARCHED = "value_searched"
    NOTE_EDITED = "note_edited"
    NOTE_DELETED = "note_deleted"
    FILE_VIEWED = "file_viewed"
    FILES_SEARCHED = "files_searched"
    RULE_CREATED = "rule_created"
    RULE_CHANGED = "rule_changed"
    RULE_DELETED = "rule_deleted"
    RULES_IMPORTED = "rules_imported"
    RULES_EXPORTED = "rules_exported"
    SECRETS_EXPORTED = "secrets_exported"
    IMPORT_STARTED = "import_started"
    IMPORT_CONFIRMED = "import_confirmed"
    IMPORT_RECORDED = "import_recorded"
    IMPORT_DISCARDED = "import_discarded"
    IMPORT_REMOVED = "import_removed"
    UPLOAD_STARTED = "upload_started"
    UPLOAD_FINISHED = "upload_finished"
    UPLOAD_DISCARDED = "upload_discarded"
    UPLOAD_MATCH_ANSWERED = "upload_match_answered"
    REPOSITORIES_DELETION_STARTED = "repositories_deletion_started"
    REPOSITORIES_DELETED = "repositories_deleted"
    AUDIT_CLEARED = "audit_cleared"
    ACCESS_REFUSED = "access_refused"
    TOOLS_DETECTED = "tools_detected"
    INSTANCE_STARTED = "instance_started"


def record(
    session: Session,
    action: AuditAction,
    *,
    actor: User | None,
    target: User | None = None,
    ip: str | None = None,
    detail: Mapping[str, AuditValue] | None = None,
    at: datetime | None = None,
    subjects: Sequence[Subject] = (),
) -> AuditEvent:
    if detail is not None and "subjects" in detail:
        raise ValueError("audit detail may not contain 'subjects': record counts them")
    clean = _clean(detail or {})
    subjects = list(dict.fromkeys(subjects))
    if subjects:
        clean["subjects"] = len(subjects)
    event = AuditEvent(
        at=at or utcnow(),
        action=action.value,
        actor_user_id=actor.id if actor else None,
        target_user_id=target.id if target else None,
        ip=ip,
        detail=clean,
    )
    session.add(event)
    session.flush()
    session.add_all(AuditSubject(event_id=event.id, **columns(subject)) for subject in subjects)
    session.flush()
    return event


def record_carried(
    session: Session,
    action: AuditAction,
    *,
    actor: User | None,
    ip: str | None,
    subjects: Sequence[Subject],
    detail: Mapping[str, AuditValue] | None = None,
    filters: Mapping[str, AuditValue] | None = None,
) -> AuditEvent:
    distinct = list(dict.fromkeys(subjects))
    if len(distinct) <= NAME_SUBJECTS_UP_TO:
        return record(session, action, actor=actor, ip=ip, detail=detail, subjects=distinct)
    counted: dict[str, AuditValue] = {
        **(detail or {}),
        "carried": len(distinct),
        "filters": dict(filters or {}),
    }
    return record(session, action, actor=actor, ip=ip, detail=counted)


def _clean(detail: Mapping[str, AuditValue]) -> dict[str, AuditValue]:
    clean: dict[str, AuditValue] = {}
    for key, value in detail.items():
        if key in FORBIDDEN_DETAIL_KEYS:
            raise ValueError(f"audit detail may not contain {key!r}")
        clean[key] = _cut(value)
    return clean


def _cut(value: AuditValue) -> AuditValue:
    if isinstance(value, str):
        return value[:MAX_DETAIL_VALUE_LENGTH]
    if isinstance(value, Mapping):
        return _clean(value)
    if isinstance(value, list):
        return [_cut(item) for item in value]
    return value


def list_events(session: Session, *, page: int, per_page: int) -> tuple[list[AuditEvent], int]:
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    total = session.scalar(select(func.count()).select_from(AuditEvent)) or 0
    rows = session.scalars(
        select(AuditEvent)
        .order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    return list(rows), total


def subjects_of(
    session: Session, event_id: int, *, page: int, per_page: int
) -> tuple[list[Subject], int]:
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    where = AuditSubject.event_id == event_id
    total = session.scalar(select(func.count()).select_from(AuditSubject).where(where)) or 0
    rows = session.execute(
        select(AuditSubject.secret_id, AuditSubject.finding_id)
        .where(where)
        .order_by(AuditSubject.id)
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    found: list[Subject] = []
    for secret_id, finding_id in rows:
        if secret_id is not None:
            found.append(Subject(SubjectKind.SECRET, secret_id))
        elif finding_id is not None:
            found.append(Subject(SubjectKind.FINDING, finding_id))
    return found, total


def clearable(session: Session, *, before: datetime | None) -> tuple[int, int | None]:
    query = select(func.count(), func.max(AuditEvent.id))
    if before is not None:
        query = query.where(AuditEvent.at < before)
    count, highest = session.execute(query).one()
    return int(count), highest


def clear_events(
    factory: Callable[[], Session],
    *,
    before: datetime | None,
    up_to_id: int | None,
    trace: Mapping[str, AuditValue],
    batch: int = CLEAR_BATCH,
) -> int:
    if up_to_id is None:
        return 0
    deleted = 0
    trace_id: int | None = None
    chosen = select(AuditEvent.id)
    while True:
        with factory() as session:
            if trace_id is None:
                trace_id = record(
                    session, AuditAction.AUDIT_CLEARED, actor=None, detail={**trace, "deleted": 0}
                ).id
                chosen = chosen.where(AuditEvent.id <= min(up_to_id, trace_id - 1))
                if before is not None:
                    chosen = chosen.where(AuditEvent.at < before)
                chosen = chosen.order_by(AuditEvent.id).limit(batch)
            result = session.execute(
                delete(AuditEvent)
                .where(AuditEvent.id.in_(chosen.scalar_subquery()))
                .execution_options(synchronize_session=False)
            )
            gone = cast(CursorResult[Any], result).rowcount
            if deleted + gone == 0:
                session.rollback()
                return 0
            deleted += gone
            session.execute(
                update(AuditEvent)
                .where(AuditEvent.id == trace_id)
                .values(detail={**trace, "deleted": deleted})
                .execution_options(synchronize_session=False)
            )
            session.commit()
        if gone < batch:
            return deleted
