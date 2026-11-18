from collections.abc import Sequence
from typing import Any

from apiflask import APIBlueprint, abort

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.crypto import SealError
from gitmortem.db.models import AuditValue, Role, Scan, ScanKind, SkipReason, ToolName
from gitmortem.scanning import progress
from gitmortem.scanning.service import ScanRefused, ScanService
from gitmortem.scanning.tools import CoverageGaps, RunDiagnosis
from gitmortem.triage.stats import scan_secrets
from gitmortem.web.actors import current_actor, may_end
from gitmortem.web.api_explorer import VALUES_403
from gitmortem.web.api_triage import VALUES_ROLE
from gitmortem.web.dbsession import get_db, read_phase
from gitmortem.web.scans import refuse, running_scans
from gitmortem.web.schemas import (
    IntegrityCountsOut,
    RereadIn,
    RereadOut,
    RunCountsOut,
    RunOutputOut,
    RunStateCountsOut,
    ScanIdOut,
    ScanIn,
    ScanOut,
    ScanPageOut,
    ScanQueryIn,
    ScanSecretsOut,
    ScanSummaryOut,
    ToolRunOut,
    ToolRunPageOut,
    described,
)
from gitmortem.web.security import client_ip, note_refusal, require_role

bp = APIBlueprint("scans", __name__, url_prefix="/api/scans")
rereads_bp = APIBlueprint("rereads", __name__, url_prefix="/api/rereads")
SCAN_ID = "<id:scan_id>"
NO_SUCH_SCAN = "No such scan."
NO_SUCH_RUN = "No such run in this scan."
OUTPUT_UNREADABLE = "The run's stored output could not be read."
SCAN_ENDED = "The scan has already ended."
NAMED_UP_TO = audit.NAME_SUBJECTS_UP_TO


def _named(ids: Sequence[int]) -> list[AuditValue]:
    named: list[AuditValue] = list(dict.fromkeys(ids))
    return named[:NAMED_UP_TO]


NOT_YOUR_SCAN = "Only the user who started this scan, or an admin, may cancel it."
IMPORT_NOT_CANCELLED = "An import is discarded, not cancelled: its own routes end it."
NOT_RUNNING_DOC = "Scanning is not running"
NOTHING_TO_REREAD_DOC: dict[str, Any] = {
    "description": "Nothing to re-read: no scan was made, and nothing was audited",
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RereadOut"}}},
}


def _summary(scan: Scan, started_by: str | None, run_count: int) -> ScanSummaryOut:
    return ScanSummaryOut(
        id=scan.id,
        kind=scan.kind,
        state=scan.state,
        started_by=started_by,
        workers=scan.workers,
        run_count=run_count,
        cancel_requested_at=scan.cancel_requested_at,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


@bp.post("", endpoint="start")
@require_role(Role.ANALYST)
@bp.input(ScanIn, arg_name="new")
@bp.output(ScanIdOut, status_code=202)
@bp.doc(
    responses={
        404: "A named scan root does not exist or was removed; nothing was written",
        422: "Refused before anything was written; the message names the first problem",
        503: NOT_RUNNING_DOC,
    }
)
def start(new: ScanIn) -> tuple[ScanIdOut, int]:
    service = running_scans()
    db = get_db()
    actor = current_actor()
    try:
        matching = None if new.matching is None else new.matching.matching()
        scan_id = service.plan_scan(
            db, new.repository_ids, actor.id, root_ids=new.scan_root_ids, matching=matching
        )
    except ScanRefused as refused:
        refuse(refused)
    detail: dict[str, AuditValue] = {
        "scan_id": scan_id,
        "repositories": len(set(new.repository_ids)),
        "roots": len(set(new.scan_root_ids)),
        "repository_ids": _named(new.repository_ids),
        "root_ids": _named(new.scan_root_ids),
    }
    if new.matching is not None:
        detail["matching"] = {
            "root_id": new.matching.scan_root_id,
            "filters": new.matching.filters.chosen(),
            "excluded_ids": _named(new.matching.excluded_ids),
            "included_ids": _named(new.matching.included_ids),
        }
    audit.record(db, AuditAction.SCAN_STARTED, actor=actor, ip=client_ip(), detail=detail)
    service.notify()
    return ScanIdOut(scan_id=scan_id), 202


@bp.get("", endpoint="list")
@require_role(Role.ANALYST)
@bp.input(ScanQueryIn, location="query", arg_name="query")
@bp.output(ScanPageOut)
@bp.doc(responses={503: NOT_RUNNING_DOC})
def list_scans(query: ScanQueryIn) -> ScanPageOut:
    running_scans()
    summaries, total = progress.list_scans(get_db(), page=query.page, per_page=query.per_page)
    return ScanPageOut(
        items=[_summary(s.scan, s.started_by, s.run_count) for s in summaries],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


@bp.get(f"/{SCAN_ID}", endpoint="get")
@require_role(Role.ANALYST)
@bp.output(ScanOut)
@bp.doc(responses={404: NO_SUCH_SCAN, 503: NOT_RUNNING_DOC})
def get_scan(scan_id: int) -> ScanOut:
    running_scans()
    db = get_db()
    scan = db.get(Scan, scan_id)
    if scan is None:
        abort(404, NO_SUCH_SCAN)
    states, integrity = progress.run_counts(db, scan_id)
    found = scan_secrets(db, scan_id)
    summary = _summary(scan, progress.started_by(db, scan), sum(states.values()))
    return ScanOut(
        **summary.model_dump(),
        counts=RunCountsOut(
            states=RunStateCountsOut(**{state.value: n for state, n in states.items()}),
            integrity=IntegrityCountsOut(**{state.value: n for state, n in integrity.items()}),
        ),
        skipped_tools={ToolName(name): SkipReason(why) for name, why in scan.skipped_tools.items()},
        secrets=ScanSecretsOut(
            findings=found.findings, unique=found.unique, new_unique=found.new_unique
        ),
    )


@bp.get(f"/{SCAN_ID}/runs", endpoint="runs")
@require_role(Role.ANALYST)
@bp.input(ScanQueryIn, location="query", arg_name="query")
@bp.output(ToolRunPageOut)
@bp.doc(responses={404: NO_SUCH_SCAN, 503: NOT_RUNNING_DOC})
def list_runs(scan_id: int, query: ScanQueryIn) -> ToolRunPageOut:
    running_scans()
    db = get_db()
    if db.get(Scan, scan_id) is None:
        abort(404, NO_SUCH_SCAN)
    rows, total = progress.scan_runs(db, scan_id, page=query.page, per_page=query.per_page)
    return ToolRunPageOut(
        items=[
            ToolRunOut(
                id=row.run.id,
                repository_id=row.run.repository_id,
                display_path=row.display_path,
                tool=row.run.tool,
                identity=row.run.identity,
                state=row.run.state,
                failure=row.run.failure,
                exit_code=row.run.exit_code,
                integrity=row.run.integrity,
                parse_issues=row.run.parse_issues,
                findings_count=row.run.findings_count,
                coverage_gaps=(
                    None
                    if row.run.coverage_gaps is None
                    else CoverageGaps.model_validate(row.run.coverage_gaps)
                ),
                diagnosis=(
                    None
                    if row.run.diagnosis is None
                    else RunDiagnosis.model_validate(row.run.diagnosis)
                ),
                has_output=row.has_output,
                canary=row.run.canary,
                kept_end=row.run.kept_end,
                reread_of_id=row.run.reread_of_id,
                superseded_by_id=row.run.superseded_by_id,
                superseded_at=row.run.superseded_at,
                started_at=row.run.started_at,
                finished_at=row.run.finished_at,
            )
            for row in rows
        ],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


@bp.get(f"/{SCAN_ID}/runs/<id:run_id>/output", endpoint="run_output")
@require_role(VALUES_ROLE)
@bp.output(RunOutputOut)
@bp.doc(responses={403: VALUES_403, 404: NO_SUCH_RUN, 422: OUTPUT_UNREADABLE, 503: NOT_RUNNING_DOC})
def run_output(scan_id: int, run_id: int) -> RunOutputOut:
    service = running_scans()
    try:
        with read_phase() as db:
            found = progress.run_output(db, service.raw_store, scan_id, run_id)
    except (SealError, OSError):
        abort(422, OUTPUT_UNREADABLE)
    if found is None:
        abort(404, NO_SUCH_RUN)
    return RunOutputOut(text=found.text, size=found.size, cut=found.cut)


@bp.post(f"/{SCAN_ID}/cancel", endpoint="cancel")
@require_role(Role.ANALYST)
@bp.output(ScanIdOut, status_code=202)
@bp.doc(
    responses={
        403: NOT_YOUR_SCAN,
        404: NO_SUCH_SCAN,
        409: f"{SCAN_ENDED} Or: {IMPORT_NOT_CANCELLED}",
        503: NOT_RUNNING_DOC,
    }
)
def cancel(scan_id: int) -> tuple[ScanIdOut, int]:
    service = running_scans()
    db = get_db()
    scan = db.get(Scan, scan_id)
    if scan is None:
        db.rollback()
        abort(404, NO_SUCH_SCAN)
    if scan.kind is ScanKind.IMPORT:
        abort(409, IMPORT_NOT_CANCELLED)
    if not may_end(scan.started_by_user_id):
        db.rollback()
        note_refusal("not_yours")
        abort(403, NOT_YOUR_SCAN, detail={"reason": "not_yours"})
    if not service.request_cancel(db, scan):
        abort(409, SCAN_ENDED)
    audit.record(
        db,
        AuditAction.SCAN_CANCELLED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"scan_id": scan_id},
    )
    service.notify()
    return ScanIdOut(scan_id=scan_id), 202


def _reread(service: ScanService, *, scan_id: int | None, stale: bool) -> tuple[RereadOut, int]:
    db = get_db()
    actor = current_actor()
    try:
        plan = service.plan_reread(db, actor.id, scan_id=scan_id, stale=stale)
    except ScanRefused as refused:
        refuse(refused)
    if plan.scan_id is None:
        return RereadOut(scan_id=None, runs=0), 200
    audit.record(
        db,
        AuditAction.SCAN_REREAD,
        actor=actor,
        ip=client_ip(),
        detail={"scan_id": plan.scan_id, "runs": len(plan.runs)},
    )
    service.notify()
    return RereadOut(scan_id=plan.scan_id, runs=len(plan.runs)), 202


@bp.post(f"/{SCAN_ID}/reread", endpoint="reread")
@require_role(Role.ANALYST)
@bp.output(RereadOut, status_code=202)
@bp.doc(
    responses=described(
        {
            200: NOTHING_TO_REREAD_DOC,
            404: NO_SUCH_SCAN,
            409: "A run of the scan is still queued or running",
            503: NOT_RUNNING_DOC,
        }
    )
)
def reread(scan_id: int) -> tuple[RereadOut, int]:
    return _reread(running_scans(), scan_id=scan_id, stale=False)


@rereads_bp.post("", endpoint="start")
@require_role(Role.ANALYST)
@rereads_bp.input(RereadIn, arg_name="asked")
@rereads_bp.output(RereadOut, status_code=202)
@rereads_bp.doc(responses=described({200: NOTHING_TO_REREAD_DOC, 503: NOT_RUNNING_DOC}))
def stale(asked: RereadIn) -> tuple[RereadOut, int]:
    return _reread(running_scans(), scan_id=None, stale=asked.stale)
