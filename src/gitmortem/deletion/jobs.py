import time
from collections.abc import Collection
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import CursorResult, or_, select, update

from gitmortem import console
from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db import truncate_journal
from gitmortem.db.models import (
    AuditValue,
    Deletion,
    DeletionFailure,
    DeletionJobState,
    DeletionState,
    Import,
    Repository,
    ToolRun,
    ToolRunState,
    User,
    utcnow,
)
from gitmortem.deletion.plan import DeletionPlan, plan_deletion, plan_digest
from gitmortem.deletion.records import Removed, finish_records, remove_batch
from gitmortem.deletion.remove import remove_under
from gitmortem.scanning.imports import JOB_STATES
from gitmortem.scanning.uow import read_only, retry_busy, unit_of_work

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from gitmortem.scanning.jobs import DeletionJob
    from gitmortem.scanning.service import ScanService

STOP_SECONDS = 60.0
MAX_FOLDERS_NAMED = 1_000
_ZERO = {"repositories": 0, "findings": 0, "secrets": 0, "with_triage": 0}


class DeletionBusy(Exception):
    pass


def start_deletion(
    session: "Session", plan: DeletionPlan, user: User | None, *, now: datetime
) -> Deletion:
    deletion = Deletion(
        requested_by_user_id=None if user is None else user.id,
        state=DeletionJobState.QUEUED,
        created_at=now,
        counts=dict(_ZERO),
        plan_digest=plan_digest(plan),
    )
    session.add(deletion)
    session.flush()
    marked = session.execute(
        update(Repository)
        .where(
            Repository.id.in_(plan.repositories),
            or_(
                Repository.deletion_state.is_(None),
                Repository.deletion_state == DeletionState.FAILED,
            ),
        )
        .values(
            deletion_state=DeletionState.DELETING, deletion_failure=None, deletion_id=deletion.id
        )
        .execution_options(synchronize_session=False)
    )
    if cast(CursorResult[Any], marked).rowcount != len(plan.repositories):
        raise DeletionBusy
    session.flush()
    return deletion


def take_deletions(session: "Session", *, held: bool) -> list[int]:
    if held:
        return []
    found = session.scalars(
        select(Deletion).where(Deletion.state == DeletionJobState.QUEUED).order_by(Deletion.id)
    ).first()
    if found is None:
        return []
    found.state = DeletionJobState.RUNNING
    found.started_at = utcnow()
    session.flush()
    return [found.id]


def has_due(session: "Session", *, held: bool) -> bool:
    if held:
        return False
    queued = select(Deletion.id).where(Deletion.state == DeletionJobState.QUEUED).limit(1)
    return session.scalar(queued) is not None


def requeue(session: "Session") -> None:
    session.execute(
        update(Deletion)
        .where(Deletion.state == DeletionJobState.RUNNING)
        .values(state=DeletionJobState.QUEUED)
        .execution_options(synchronize_session=False)
    )


def _stop_jobs(service: "ScanService", repository_ids: list[int]) -> bool:
    with unit_of_work(service.engine) as session:
        now = utcnow()
        session.execute(
            update(ToolRun)
            .where(ToolRun.repository_id.in_(repository_ids), ToolRun.state == ToolRunState.QUEUED)
            .values(state=ToolRunState.CANCELLED, finished_at=now)
            .execution_options(synchronize_session=False)
        )
        running = list(
            session.scalars(
                select(ToolRun.id).where(
                    ToolRun.repository_id.in_(repository_ids),
                    ToolRun.state == ToolRunState.RUNNING,
                )
            )
        )
        importing = list(
            session.scalars(
                select(Import.id).where(
                    Import.repository_id.in_(repository_ids), Import.state.in_(JOB_STATES)
                )
            )
        )
    service.stop_runs(running)
    service.stop_imports(importing)
    until = time.monotonic() + STOP_SECONDS
    while time.monotonic() < until:
        with read_only(service.engine) as session:
            left = session.scalar(
                select(ToolRun.id)
                .where(
                    ToolRun.repository_id.in_(repository_ids),
                    ToolRun.state == ToolRunState.RUNNING,
                )
                .limit(1)
            )
        if left is None and not service.holds_imports(importing):
            return True
        time.sleep(0.2)
    return False


def _fail(
    service: "ScanService", repository_ids: Collection[int], failure: DeletionFailure
) -> None:
    if not repository_ids:
        return

    def write(session: "Session") -> None:
        session.execute(
            update(Repository)
            .where(
                Repository.id.in_(list(repository_ids)),
                Repository.deletion_state == DeletionState.DELETING,
            )
            .values(deletion_state=DeletionState.FAILED, deletion_failure=failure)
            .execution_options(synchronize_session=False)
        )

    retry_busy(service.engine, write)


def _add(session: "Session", deletion_id: int, **more: int) -> None:
    row = session.get(Deletion, deletion_id)
    if row is None:
        return
    counts = {**_ZERO, **row.counts}
    for name, value in more.items():
        counts[name] += value
    row.counts = counts


def _remove_records(service: "ScanService", deletion_id: int, repository_id: int) -> None:
    def batch(session: "Session") -> Removed | None:
        removed = remove_batch(session, [repository_id])
        if removed is not None:
            _add(
                session,
                deletion_id,
                findings=removed.findings,
                secrets=removed.secrets,
                with_triage=removed.with_triage,
            )
        return removed

    while retry_busy(service.engine, batch) is not None:
        pass

    def last(session: "Session") -> None:
        finish_records(session, service.raw_store, [repository_id], now=utcnow())
        _add(session, deletion_id, repositories=1)

    retry_busy(service.engine, last)


def _finish(service: "ScanService", deletion_id: int, left: list[str], removed: list[str]) -> None:
    def write(session: "Session") -> None:
        row = session.get(Deletion, deletion_id)
        if row is None:
            return
        now = utcnow()
        session.execute(
            update(Repository)
            .where(
                Repository.deletion_id == deletion_id,
                Repository.deletion_state == DeletionState.DELETING,
            )
            .values(
                deletion_state=DeletionState.FAILED,
                deletion_failure=DeletionFailure.UNEXPECTED_ERROR,
            )
            .execution_options(synchronize_session=False)
        )
        outcome = session.execute(
            select(Repository.id, Repository.deletion_state)
            .where(Repository.deletion_id == deletion_id)
            .order_by(Repository.id)
        ).all()
        counts = {**_ZERO, **row.counts}
        row.state = DeletionJobState.DONE
        row.finished_at = now
        audit.record(
            session,
            AuditAction.REPOSITORIES_DELETED,
            actor=None,
            detail={
                "deletion_id": deletion_id,
                "deleted": list[AuditValue](
                    [rid for rid, state in outcome if state is DeletionState.DELETED]
                ),
                "failed": list[AuditValue](
                    [rid for rid, state in outcome if state is DeletionState.FAILED]
                ),
                "left": list[AuditValue](left),
                "removed": list[AuditValue](removed[:MAX_FOLDERS_NAMED]),
                "removed_total": len(removed),
                "findings": counts["findings"],
                "secrets": counts["secrets"],
                "with_triage": counts["with_triage"],
            },
            at=now,
        )

    retry_busy(service.engine, write)
    truncate_journal(service.engine)


class _Stopped(Exception):
    pass


def _carry_out(
    service: "ScanService", job: "DeletionJob", plan: DeletionPlan, removed: list[str]
) -> None:
    deletion_id = job.id
    repository_ids = list(plan.repositories)
    if not _stop_jobs(service, repository_ids):
        _fail(service, repository_ids, DeletionFailure.SCANS_STILL_RUNNING)
        return
    blocked: set[int] = set()
    for removal in plan.removals:
        if job.cancel.is_set():
            raise _Stopped
        outcome = remove_under(
            removal.base,
            removal.root,
            removal.rel,
            keep_top=removal.keep_top,
            identity=removal.identity,
        )
        if outcome is None:
            removed.append(removal.display)
        else:
            blocked |= {removal.repository_id, *removal.covers}
    _fail(service, sorted(blocked), DeletionFailure.FILES_NOT_DELETED)
    for repository_id in repository_ids:
        if repository_id in blocked:
            continue
        if job.cancel.is_set():
            raise _Stopped
        try:
            _remove_records(service, deletion_id, repository_id)
        except Exception as exc:
            console.error(f"deletion {deletion_id} failed ({type(exc).__name__})")
            _fail(service, [repository_id], DeletionFailure.UNEXPECTED_ERROR)


def run_deletion(service: "ScanService", job: "DeletionJob") -> None:
    with read_only(service.engine) as session:
        deletion = session.get(Deletion, job.id)
        if deletion is None:
            return
        confirmed = deletion.plan_digest
        repository_ids = list(
            session.scalars(
                select(Repository.id).where(
                    Repository.deletion_id == job.id,
                    Repository.deletion_state == DeletionState.DELETING,
                )
            )
        )
        plan = plan_deletion(
            session, service.runner, service.settings, repository_ids, deletion_id=job.id
        )
    removed: list[str] = []
    stopped = False
    try:
        if not repository_ids:
            return
        if plan_digest(plan) != confirmed or set(plan.repositories) != set(repository_ids):
            _fail(service, repository_ids, DeletionFailure.PLAN_CHANGED)
            return
        _carry_out(service, job, plan, removed)
    except _Stopped:
        stopped = True
    finally:
        if not stopped:
            _finish(service, job.id, [folder.display for folder in plan.left], removed)
