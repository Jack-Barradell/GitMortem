from apiflask import APIBlueprint, abort
from sqlalchemy import select

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import DiscoveryRun, Role, User
from gitmortem.web.actors import current_actor, may_end
from gitmortem.web.dbsession import get_db
from gitmortem.web.scans import running_scans
from gitmortem.web.schemas import DiscoveryIdOut, DiscoveryOut
from gitmortem.web.security import client_ip, note_refusal, require_role

bp = APIBlueprint("discoveries", __name__, url_prefix="/api/discoveries")
DISCOVERY_ID = "<id:discovery_id>"
NO_SUCH_DISCOVERY = "No such discovery."
DISCOVERY_ENDED = "The discovery has already ended."
NOT_YOUR_DISCOVERY = "Only the user who started this discovery, or an admin, may cancel it."
NOT_RUNNING_DOC = "Scanning is not running"


@bp.get(f"/{DISCOVERY_ID}", endpoint="get")
@require_role(Role.ANALYST)
@bp.output(DiscoveryOut)
@bp.doc(responses={404: NO_SUCH_DISCOVERY, 503: NOT_RUNNING_DOC})
def get_discovery(discovery_id: int) -> DiscoveryOut:
    running_scans()
    db = get_db()
    run = db.get(DiscoveryRun, discovery_id)
    if run is None:
        abort(404, NO_SUCH_DISCOVERY)
    started_by = (
        None
        if run.started_by_user_id is None
        else db.scalar(select(User.username).where(User.id == run.started_by_user_id))
    )
    return DiscoveryOut(
        id=run.id,
        scan_root_id=run.scan_root_id,
        state=run.state,
        found=run.found,
        refused=run.refused,
        aliases=run.aliases,
        not_followed=run.not_followed,
        started_by=started_by,
        cancel_requested_at=run.cancel_requested_at,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@bp.post(f"/{DISCOVERY_ID}/cancel", endpoint="cancel")
@require_role(Role.ANALYST)
@bp.output(DiscoveryIdOut, status_code=202)
@bp.doc(
    responses={
        403: NOT_YOUR_DISCOVERY,
        404: NO_SUCH_DISCOVERY,
        409: DISCOVERY_ENDED,
        503: NOT_RUNNING_DOC,
    }
)
def cancel(discovery_id: int) -> tuple[DiscoveryIdOut, int]:
    service = running_scans()
    db = get_db()
    run = db.get(DiscoveryRun, discovery_id)
    if run is None:
        db.rollback()
        abort(404, NO_SUCH_DISCOVERY)
    if not may_end(run.started_by_user_id):
        db.rollback()
        note_refusal("not_yours")
        abort(403, NOT_YOUR_DISCOVERY, detail={"reason": "not_yours"})
    if not service.request_cancel(db, run):
        db.rollback()
        abort(409, DISCOVERY_ENDED)
    audit.record(
        db,
        AuditAction.DISCOVERY_CANCELLED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"discovery_id": discovery_id, "root_id": run.scan_root_id},
    )
    service.notify()
    return DiscoveryIdOut(discovery_id=discovery_id), 202
