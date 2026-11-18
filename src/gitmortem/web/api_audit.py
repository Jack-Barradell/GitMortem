from apiflask import APIBlueprint, abort
from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.accounts.audit import list_events, subjects_of
from gitmortem.db.models import AuditEvent, Finding, Role, Secret, User
from gitmortem.triage.subjects import Subject, SubjectKind
from gitmortem.web.dbsession import get_db
from gitmortem.web.schemas import (
    AuditEventOut,
    AuditPageOut,
    AuditQueryIn,
    AuditSubjectOut,
    AuditSubjectPageOut,
)
from gitmortem.web.security import require_role

bp = APIBlueprint("audit", __name__, url_prefix="/api/audit")


@bp.get("", endpoint="list")
@require_role(Role.ADMIN)
@bp.input(AuditQueryIn, location="query", arg_name="query")
@bp.output(AuditPageOut)
def list_audit(query: AuditQueryIn) -> AuditPageOut:
    db = get_db()
    events, total = list_events(db, page=query.page, per_page=query.per_page)
    ids = {i for e in events for i in (e.actor_user_id, e.target_user_id) if i is not None}
    names = {
        row.id: row.username
        for row in db.execute(select(User.id, User.username).where(User.id.in_(ids)))
    }
    return AuditPageOut(
        items=[
            AuditEventOut(
                id=e.id,
                at=e.at,
                action=e.action,
                actor_username=names.get(e.actor_user_id),
                target_username=names.get(e.target_user_id),
                ip=e.ip,
                detail=e.detail,
            )
            for e in events
        ],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


@bp.get("/<id:event_id>/subjects", endpoint="subjects")
@require_role(Role.ADMIN)
@bp.input(AuditQueryIn, location="query", arg_name="query")
@bp.output(AuditSubjectPageOut)
def audit_subjects(event_id: int, query: AuditQueryIn) -> AuditSubjectPageOut:
    db = get_db()
    if db.get(AuditEvent, event_id) is None:
        abort(404, "No such audit event.")
    subjects, total = subjects_of(db, event_id, page=query.page, per_page=query.per_page)
    return AuditSubjectPageOut(
        items=[_subject_out(db, subject) for subject in subjects],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


def _subject_out(db: Session, subject: Subject) -> AuditSubjectOut:
    if subject.kind is SubjectKind.SECRET:
        secret = db.get(Secret, subject.id)
        label = secret.kind if secret else ""
        removed = secret is None
    else:
        finding = db.get(Finding, subject.id)
        label = finding.rule if finding else ""
        removed = finding is None
    return AuditSubjectOut(kind=subject.kind, id=subject.id, kind_label=label, removed=removed)
