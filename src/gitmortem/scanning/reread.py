import functools
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import ColumnElement, and_, exists, false, func, or_, select, update
from sqlalchemy.orm import Session, aliased

from gitmortem import console
from gitmortem.crypto import SealError
from gitmortem.db.models import (
    CanaryState,
    Import,
    Scan,
    ScanKind,
    ScanState,
    ToolName,
    ToolRun,
    ToolRunFailure,
    ToolRunState,
    utcnow,
)
from gitmortem.explorer.access import Unavailable, open_for_read
from gitmortem.gitrun import GitCancelled, GitError, GitTimeout
from gitmortem.scanning import import_jobs
from gitmortem.scanning.current import ENDED_RUN, UNFINISHED_RUN, being_deleted
from gitmortem.scanning.jobs import RereadJob, rechecked_git_dir, record_batch
from gitmortem.scanning.run import Progress
from gitmortem.scanning.settings import get_scan_workers
from gitmortem.scanning.tools import Reading, ToolSpec, with_error
from gitmortem.scanning.uow import read_only, unit_of_work

if TYPE_CHECKING:
    from gitmortem.scanning.service import ScanService

__all__ = [
    "KEPT_STATES",
    "RereadPlan",
    "plan_reread",
    "run_reread",
]

KEPT_STATES = frozenset({ToolRunState.TIMED_OUT, ToolRunState.CANCELLED, ToolRunState.INTERRUPTED})


def _rereadable(stale: bool, tools: Mapping[ToolName, ToolSpec]) -> list[ColumnElement[bool]]:
    pending = aliased(ToolRun)
    original = aliased(ToolRun)
    in_flight = exists().where(
        pending.reread_of_id == ToolRun.id, pending.state.in_(UNFINISHED_RUN)
    )
    finished_reread = exists().where(
        original.id == ToolRun.reread_of_id, original.superseded_by_id == ToolRun.id
    )
    where = [
        ToolRun.superseded_at.is_(None),
        ToolRun.state.in_(ENDED_RUN),
        ToolRun.tool.in_(list(tools)),
        ToolRun.repository_id.not_in(being_deleted(or_deleted=True)),
        or_(ToolRun.failure.is_(None), ToolRun.failure != ToolRunFailure.OUTSIDE_ROOT),
        ~in_flight,
        or_(ToolRun.reread_of_id.is_(None), finished_reread),
    ]
    if stale:
        reader = aliased(ToolRun)

        def read_today(version: int) -> ColumnElement[bool]:
            return exists().where(
                reader.reread_of_id == ToolRun.id,
                reader.parser_version >= version,
                reader.state.in_(ENDED_RUN),
            )

        older = (
            and_(
                ToolRun.tool == name,
                ToolRun.parser_version < spec.parser_version,
                ~read_today(spec.parser_version),
            )
            for name, spec in tools.items()
        )
        where.append(or_(false(), *older))
    return where


@dataclass(frozen=True)
class RereadPlan:
    scan_id: int | None
    runs: tuple[int, ...] = ()


def plan_reread(
    session: Session,
    user_id: int | None,
    *,
    scan_id: int | None,
    stale: bool,
    tools: Mapping[ToolName, ToolSpec],
) -> RereadPlan:
    if scan_id is None and not stale:
        raise ValueError("a re-read names a scan, or asks for every run an older parser judged")
    parts = aliased(ToolRun)
    query = (
        select(ToolRun, parts.raw_parts)
        .join(parts, parts.id == func.coalesce(ToolRun.parts_run_id, ToolRun.id))
        .where(*_rereadable(stale, tools))
        .order_by(ToolRun.id)
    )
    if scan_id is not None:
        query = query.where(ToolRun.scan_id == scan_id)
    picked = [run for run, sealed in session.execute(query) if sealed]
    if not picked:
        return RereadPlan(None)
    scan = Scan(
        state=ScanState.QUEUED,
        kind=ScanKind.REREAD,
        workers=get_scan_workers(session),
        started_by_user_id=user_id,
        created_at=utcnow(),
    )
    session.add(scan)
    session.flush()
    made = [
        ToolRun(
            scan_id=scan.id,
            repository_id=run.repository_id,
            tool=run.tool,
            identity=run.identity,
            state=ToolRunState.QUEUED,
            integrity=run.integrity,
            exit_code=run.exit_code,
            diagnosis=run.diagnosis,
            canary=run.canary,
            canary_commit=run.canary_commit,
            timeout_seconds=run.timeout_seconds,
            options=run.options,
            reread_of_id=run.id,
            parts_run_id=run.parts_run_id or run.id,
        )
        for run in picked
    ]
    session.add_all(made)
    session.flush()
    return RereadPlan(scan.id, tuple(run.id for run in made))


@dataclass(frozen=True)
class _Planned:
    tool: ToolName
    repository_id: int
    timeout: float
    exit_code: int | None
    canary_commit: str | None
    first_state: ToolRunState
    first_failure: ToolRunFailure | None
    first_parser_version: int | None
    parts_scan_id: int
    parts_run_id: int
    parts: frozenset[str] = field(repr=False)
    captured_at: datetime | None
    imported_pieces: int | None = None


@dataclass(frozen=True)
class _End:
    state: ToolRunState
    failure: ToolRunFailure | None = None
    finished: bool = False
    stopped: bool = False
    kept: bool = False
    judged: bool = False
    canary: CanaryState | None = None


def _planned(session: Session, run_id: int) -> _Planned:
    parts = aliased(ToolRun)
    run, owner, pieces = session.execute(
        select(ToolRun, parts, Import.pieces)
        .join(parts, parts.id == ToolRun.parts_run_id)
        .outerjoin(Import, Import.scan_id == parts.scan_id)
        .where(ToolRun.id == run_id)
    ).one()
    return _Planned(
        tool=run.tool,
        repository_id=run.repository_id,
        timeout=float(run.timeout_seconds),
        exit_code=run.exit_code,
        canary_commit=run.canary_commit,
        first_state=owner.state,
        first_failure=owner.failure,
        first_parser_version=owner.parser_version,
        parts_scan_id=owner.scan_id,
        parts_run_id=owner.id,
        parts=frozenset(owner.raw_parts),
        captured_at=owner.started_at or owner.finished_at,
        imported_pieces=pieces,
    )


def _repository(planned: _Planned, found: Path | Unavailable) -> Path | ToolRunFailure | None:
    if found is Unavailable.NOT_ON_DISK and planned.imported_pieces is not None:
        return None
    if isinstance(found, Unavailable):
        return ToolRunFailure.REPOSITORY_UNAVAILABLE
    return found


def _kept(planned: _Planned) -> bool:
    return planned.first_state in KEPT_STATES or (
        planned.first_state is ToolRunState.FAILED and planned.first_parser_version is None
    )


def _reread(service: "ScanService", job: RereadJob, progress: Progress) -> _End:
    with read_only(service.engine) as session:
        planned = _planned(session, job.id)
        read = open_for_read(session, planned.repository_id)
    spec = service.tools[planned.tool]
    try:
        if job.cancel.is_set():
            raise GitCancelled("re-read", command="re-read")
        git_dir = _repository(planned, rechecked_git_dir(service, read, planned.timeout))
        if isinstance(git_dir, ToolRunFailure):
            return _End(ToolRunState.FAILED, git_dir)
        progress.parser_version = spec.parser_version
        report = (
            None
            if planned.imported_pieces is None
            else import_jobs.imported_report(planned.tool, planned.imported_pieces)
        )
        reading = Reading(
            runner=service.runner,
            git_dir=git_dir,
            raw_store=service.raw_store,
            scan_id=planned.parts_scan_id,
            run_id=planned.parts_run_id,
            parts=planned.parts if report is None else frozenset({report.part}),
            timeout=planned.timeout,
            cancel=job.cancel,
            record=functools.partial(
                record_batch,
                service,
                job.id,
                first_seen_at=planned.captured_at,
                imported=report is not None,
            ),
            progress=progress,
            exit_code=planned.exit_code,
            canary_commit=planned.canary_commit,
            imported=report,
        )
        if report is not None:
            verdict = import_jobs.judge_import(spec, reading)
        elif _kept(planned):
            found = spec.read_output(reading)
            progress.coverage_gaps = found.coverage_gaps
            failed = planned.first_state is ToolRunState.FAILED
            kept = planned.first_failure if failed else None
            return _End(planned.first_state, kept, finished=not found.refused, kept=True)
        else:
            verdict = spec.judge_output(reading)
    except GitCancelled:
        return _End(ToolRunState.CANCELLED, stopped=True)
    except GitTimeout:
        return _End(ToolRunState.TIMED_OUT)
    except (GitError, SealError):
        return _End(ToolRunState.FAILED, ToolRunFailure.UNREADABLE)
    if verdict.read is not None:
        progress.coverage_gaps = verdict.read.coverage_gaps
    through = verdict.read is None or not verdict.read.refused
    return _End(
        verdict.state, verdict.failure, finished=through, judged=True, canary=verdict.canary
    )


def run_reread(service: "ScanService", job: RereadJob) -> None:
    progress = Progress()
    try:
        end = _reread(service, job, progress)
    except Exception as exc:
        console.error(f"tool run {job.id} ended with an unexpected error ({type(exc).__name__})")
        progress.failed_with(exc)
        end = _End(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_ERROR)
    state = end.state
    if end.stopped and service.stopping:
        state = ToolRunState.INTERRUPTED
    with unit_of_work(service.engine) as session:
        run = session.scalars(
            select(ToolRun).where(ToolRun.id == job.id, ToolRun.state == ToolRunState.RUNNING)
        ).one_or_none()
        if run is None:
            return
        now = utcnow()
        run.state = state
        run.failure = end.failure
        run.parse_issues = progress.parse_issues
        run.parser_version = None if end.stopped else progress.parser_version
        run.kept_end = end.kept
        gaps = progress.coverage_gaps
        run.coverage_gaps = None if gaps is None else gaps.model_dump()
        if progress.error is not None:
            run.diagnosis = with_error(run.diagnosis, progress.error)
        run.finished_at = now
        if end.judged:
            run.canary = end.canary
        if end.finished:
            original = aliased(ToolRun)
            finished = exists().where(
                original.id == ToolRun.reread_of_id, original.superseded_by_id == ToolRun.id
            )
            unfinished = and_(
                ToolRun.reread_of_id == run.reread_of_id,
                ToolRun.id != run.id,
                ToolRun.state.in_(ENDED_RUN),
                ~finished,
            )
            session.execute(
                update(ToolRun)
                .where(
                    or_(ToolRun.id == run.reread_of_id, unfinished),
                    ToolRun.superseded_at.is_(None),
                )
                .values(superseded_at=now, superseded_by_id=run.id)
                .execution_options(synchronize_session=False)
            )
