import functools
import os
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import BindParameter, bindparam, func, select, update
from sqlalchemy.orm import Session

from gitmortem import console
from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.crypto import SealError
from gitmortem.db.models import (
    Import,
    ImportFailure,
    ImportSource,
    ImportState,
    Scan,
    ScanState,
    ToolName,
    ToolRun,
    ToolRunFailure,
    ToolRunState,
    utcnow,
)
from gitmortem.explorer.access import Unavailable, open_for_read
from gitmortem.gitrun import GitCancelled, GitError, GitTimeout
from gitmortem.scanning.current import being_deleted
from gitmortem.scanning.imports import (
    FILE_CHANGED,
    IMPORTABLE,
    JOB_STATES,
    MAX_PIECE_BYTES,
    NOT_STORED,
    PIECE_UNREADABLE,
    UNREADABLE_REASONS,
    ImportRefusal,
    ImportRefused,
    open_server_file,
    own_run,
    own_scan,
)
from gitmortem.scanning.jobs import ImportJob, rechecked_git_dir, record_batch
from gitmortem.scanning.run import Progress
from gitmortem.scanning.streams import BOUND_REFUSALS
from gitmortem.scanning.tools import (
    UPLOAD_PART,
    ImportedReport,
    ImportTally,
    ParsedFinding,
    Reading,
    RecordFindings,
    ToolSpec,
    Verdict,
)
from gitmortem.scanning.uow import read_only, unit_of_work

if TYPE_CHECKING:
    from gitmortem.scanning.service import ScanService

__all__ = [
    "has_due",
    "import_failure",
    "imported_report",
    "judge_import",
    "requeue",
    "run_import",
    "take_imports",
]

_RUN_FAILURE: Mapping[ImportFailure, ToolRunFailure] = {
    ImportFailure.WRONG_FORMAT: ToolRunFailure.UNEXPECTED_OUTPUT,
    ImportFailure.NO_COMMITS: ToolRunFailure.UNEXPECTED_OUTPUT,
    ImportFailure.HOSTED_SOURCE: ToolRunFailure.UNEXPECTED_OUTPUT,
    ImportFailure.TOO_LARGE: ToolRunFailure.UNEXPECTED_OUTPUT,
    ImportFailure.UNREADABLE: ToolRunFailure.UNEXPECTED_OUTPUT,
    ImportFailure.REPOSITORY_UNAVAILABLE: ToolRunFailure.REPOSITORY_UNAVAILABLE,
    ImportFailure.UNEXPECTED_ERROR: ToolRunFailure.UNEXPECTED_ERROR,
}


def _ids(name: str, ids: Collection[int]) -> BindParameter[int]:
    return bindparam(name, sorted(ids), expanding=True, literal_execute=True)


def take_imports(
    session: Session, now: datetime, *, limit: int, held: Collection[int]
) -> list[int]:
    due = list(
        session.scalars(
            select(Import)
            .where(
                Import.state.in_(JOB_STATES),
                Import.id.not_in(_ids("held", held)),
                Import.repository_id.not_in(being_deleted()),
            )
            .order_by(Import.id)
            .limit(limit)
        )
    )
    for imported in due:
        session.execute(
            update(ToolRun)
            .where(ToolRun.scan_id == imported.scan_id, ToolRun.reread_of_id.is_(None))
            .values(state=ToolRunState.RUNNING, started_at=func.coalesce(ToolRun.started_at, now))
            .execution_options(synchronize_session=False)
        )
        session.execute(
            update(Scan)
            .where(Scan.id == imported.scan_id)
            .values(state=ScanState.RUNNING, started_at=func.coalesce(Scan.started_at, now))
            .execution_options(synchronize_session=False)
        )
    return [imported.id for imported in due]


def has_due(session: Session, held: Collection[int]) -> bool:
    found = select(Import.id).where(
        Import.state.in_(JOB_STATES),
        Import.id.not_in(_ids("held", held)),
        Import.repository_id.not_in(being_deleted()),
    )
    return session.scalar(found.limit(1)) is not None


def _requeued(session: Session, import_ids: Collection[int]) -> None:
    scans = select(Import.scan_id).where(Import.id.in_(_ids("i", import_ids)))
    session.execute(
        update(ToolRun)
        .where(ToolRun.scan_id.in_(scans), ToolRun.state == ToolRunState.RUNNING)
        .values(state=ToolRunState.QUEUED)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(Scan)
        .where(Scan.id.in_(scans), Scan.state == ScanState.RUNNING)
        .values(state=ScanState.QUEUED)
        .execution_options(synchronize_session=False)
    )


def requeue(session: Session) -> None:
    _requeued(session, list(session.scalars(select(Import.id).where(Import.state.in_(JOB_STATES)))))


@dataclass(frozen=True)
class _Planned:
    import_id: int
    scan_id: int
    run_id: int
    tool: ToolName
    repository_id: int
    state: ImportState
    source: ImportSource
    server_path: str | None
    size_bytes: int
    pieces: int
    pieces_received: int
    timeout: float


def _planned(session: Session, import_id: int) -> _Planned:
    imported = session.scalars(select(Import).where(Import.id == import_id)).one()
    run = own_run(session, imported)
    return _Planned(
        import_id=imported.id,
        scan_id=imported.scan_id,
        run_id=run.id,
        tool=imported.tool,
        repository_id=imported.repository_id,
        state=imported.state,
        source=imported.source,
        server_path=imported.server_path,
        size_bytes=imported.size_bytes,
        pieces=imported.pieces,
        pieces_received=imported.pieces_received,
        timeout=float(run.timeout_seconds),
    )


@dataclass
class _Counted:
    values: int = 0
    standalone: int = 0
    reported_live: int = 0

    def __call__(self, batch: Sequence[ParsedFinding]) -> None:
        for finding in batch:
            if finding.value is None:
                self.standalone += 1
            else:
                self.values += 1
            if finding.reported_live:
                self.reported_live += 1


@dataclass(frozen=True)
class _Failed:
    failure: ImportFailure
    reason: str | None = None
    run_state: ToolRunState = ToolRunState.FAILED


class _Stopped(Exception):
    pass


def import_failure(tally: ImportTally) -> tuple[ImportFailure | None, str | None]:
    if tally.refusal in BOUND_REFUSALS:
        return ImportFailure.UNREADABLE, tally.refusal
    if tally.records == 0 and (tally.refusal is not None or tally.unreadable > 0):
        return ImportFailure.WRONG_FORMAT, None
    if tally.hosted:
        return ImportFailure.HOSTED_SOURCE, None
    if tally.uncommitted:
        return ImportFailure.NO_COMMITS, None
    if tally.refusal is not None:
        reason = tally.refusal if tally.refusal in UNREADABLE_REASONS else None
        return ImportFailure.UNREADABLE, reason
    return None, None


def judge_import(spec: ToolSpec, reading: Reading) -> Verdict:
    imported = reading.imported
    if imported is None:
        raise TypeError("only an import's reading is judged as one")
    read = spec.read_output(reading)
    failure, _ = import_failure(imported.tally)
    if failure is None and read.whole:
        return Verdict(ToolRunState.DONE, read=read)
    return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, read=read)


def imported_report(tool: ToolName, pieces: int) -> ImportedReport:
    return ImportedReport(IMPORTABLE[tool], pieces)


def _reading(
    service: "ScanService",
    job: ImportJob,
    planned: _Planned,
    git_dir: Path | None,
    record: RecordFindings,
    progress: Progress,
    report: ImportedReport,
) -> Reading:
    return Reading(
        runner=service.runner,
        git_dir=git_dir,
        raw_store=service.raw_store,
        scan_id=planned.scan_id,
        run_id=planned.run_id,
        parts=frozenset({report.part}),
        timeout=planned.timeout,
        cancel=job.cancel,
        record=record,
        progress=progress,
        imported=report,
    )


def _git_dir(service: "ScanService", planned: _Planned) -> Path | _Failed | None:
    with read_only(service.engine) as session:
        read = open_for_read(session, planned.repository_id)
    found = rechecked_git_dir(service, read, planned.timeout)
    if found is Unavailable.NOT_ON_DISK:
        return None
    if isinstance(found, Unavailable):
        return _Failed(ImportFailure.REPOSITORY_UNAVAILABLE)
    return found


def _read_exactly(descriptor: int, size: int) -> bytes:
    pieces: list[bytes] = []
    got = 0
    while got < size:
        chunk = os.read(descriptor, size - got)
        if not chunk:
            break
        pieces.append(chunk)
        got += len(chunk)
    return b"".join(pieces)


def _seal_server_file(service: "ScanService", job: ImportJob, planned: _Planned) -> _Failed | None:
    try:
        found, descriptor = open_server_file(planned.server_path or "", service.settings)
    except ImportRefused as refused:
        if refused.reason is ImportRefusal.TOO_LARGE:
            return _Failed(ImportFailure.TOO_LARGE)
        return _Failed(ImportFailure.UNREADABLE, FILE_CHANGED)
    try:
        if str(found.path) != planned.server_path or found.size_bytes != planned.size_bytes:
            return _Failed(ImportFailure.UNREADABLE, FILE_CHANGED)
        for seq in range(1, planned.pieces + 1):
            if job.cancel.is_set():
                raise _Stopped
            wanted = (
                MAX_PIECE_BYTES
                if seq < planned.pieces
                else planned.size_bytes - (planned.pieces - 1) * MAX_PIECE_BYTES
            )
            data = _read_exactly(descriptor, wanted)
            if len(data) != wanted:
                return _Failed(ImportFailure.UNREADABLE, FILE_CHANGED)
            try:
                service.raw_store.write_bytes(
                    planned.scan_id, planned.run_id, f"{UPLOAD_PART}-{seq:05d}", data
                )
            except OSError:
                return _Failed(ImportFailure.UNEXPECTED_ERROR, NOT_STORED)
        if os.read(descriptor, 1):
            return _Failed(ImportFailure.UNREADABLE, FILE_CHANGED)
    except OSError:
        return _Failed(ImportFailure.UNREADABLE, FILE_CHANGED)
    finally:
        os.close(descriptor)
    with unit_of_work(service.engine) as session:
        session.execute(
            update(Import)
            .where(Import.id == planned.import_id)
            .values(pieces_received=planned.pieces)
            .execution_options(synchronize_session=False)
        )
    return None


@dataclass(frozen=True)
class _Checked:
    check: dict[str, int]
    failure: ImportFailure | None = None
    reason: str | None = None


def _check(service: "ScanService", job: ImportJob, planned: _Planned) -> _Checked | _Failed:
    spec = service.tools[planned.tool]
    if planned.source is ImportSource.SERVER_FILE and planned.pieces_received < planned.pieces:
        sealed = _seal_server_file(service, job, planned)
        if sealed is not None:
            return sealed
    git_dir = _git_dir(service, planned)
    if isinstance(git_dir, _Failed):
        return git_dir
    counted = _Counted()
    progress = Progress()
    report = imported_report(planned.tool, planned.pieces)
    reading = _reading(service, job, planned, git_dir, counted, progress, report)
    try:
        spec.read_output(reading)
    except GitCancelled:
        raise _Stopped from None
    except GitError:
        return _Failed(ImportFailure.REPOSITORY_UNAVAILABLE)
    except SealError:
        return _Failed(ImportFailure.UNREADABLE, PIECE_UNREADABLE)
    tally = report.tally
    check = {
        "records": tally.records,
        "values": counted.values,
        "standalone": counted.standalone,
        "redacted": tally.redacted,
        "unknown_commits": len(tally.unknown_commits),
        "parse_issues": progress.parse_issues,
        "reported_live": counted.reported_live,
    }
    failure, reason = import_failure(tally)
    return _Checked(check, failure, reason)


@dataclass(frozen=True)
class _Recorded:
    verdict: Verdict
    progress: Progress
    failure: ImportFailure | None = None
    reason: str | None = None


def _record(service: "ScanService", job: ImportJob, planned: _Planned) -> _Recorded | _Failed:
    spec = service.tools[planned.tool]
    git_dir = _git_dir(service, planned)
    if isinstance(git_dir, _Failed):
        return git_dir
    progress = Progress(parser_version=spec.parser_version)
    record = functools.partial(record_batch, service, planned.run_id, imported=True)
    report = imported_report(planned.tool, planned.pieces)
    reading = _reading(service, job, planned, git_dir, record, progress, report)
    try:
        verdict = judge_import(spec, reading)
    except GitCancelled:
        raise _Stopped from None
    except GitTimeout:
        return _Failed(ImportFailure.REPOSITORY_UNAVAILABLE, run_state=ToolRunState.TIMED_OUT)
    except GitError:
        return _Failed(ImportFailure.REPOSITORY_UNAVAILABLE)
    except SealError:
        return _Failed(ImportFailure.UNREADABLE, PIECE_UNREADABLE)
    failure, reason = import_failure(report.tally)
    return _Recorded(verdict, progress, failure, reason)


def run_import(service: "ScanService", job: ImportJob) -> None:
    with read_only(service.engine) as session:
        planned = _planned(session, job.id)
    end: _Checked | _Recorded | _Failed
    try:
        end = (
            _check(service, job, planned)
            if planned.state is ImportState.CHECKING
            else _record(service, job, planned)
        )
    except _Stopped:
        with unit_of_work(service.engine) as session:
            _requeued(session, [planned.import_id])
        return
    except Exception as exc:
        console.error(f"import {job.id} ended with an unexpected error ({type(exc).__name__})")
        end = _Failed(ImportFailure.UNEXPECTED_ERROR)
    _end(service, planned, end)


def _end(service: "ScanService", planned: _Planned, end: _Checked | _Recorded | _Failed) -> None:
    now = utcnow()
    drop_parts = False
    with unit_of_work(service.engine) as session:
        imported = session.scalars(select(Import).where(Import.id == planned.import_id)).one()
        if imported.state is not planned.state:
            return
        run = own_run(session, imported)
        scan = own_scan(session, imported)
        if isinstance(end, _Checked):
            imported.check = end.check
            if end.failure is None:
                imported.state = ImportState.CHECKED
                imported.checked_at = now
                run.state = ToolRunState.QUEUED
                scan.state = ScanState.QUEUED
                return
            end = _Failed(end.failure, end.reason)
        run.finished_at = now
        scan.state = ScanState.FINISHED
        scan.finished_at = now
        if isinstance(end, _Recorded):
            run.state = end.verdict.state
            run.failure = end.verdict.failure
            run.parse_issues = end.progress.parse_issues
            run.parser_version = end.progress.parser_version
            run.raw_parts = [f"{UPLOAD_PART}-{seq:05d}" for seq in range(1, planned.pieces + 1)]
            if end.verdict.state is ToolRunState.DONE:
                imported.state = ImportState.RECORDED
                imported.recorded_at = now
                audit.record(
                    session,
                    AuditAction.IMPORT_RECORDED,
                    actor=None,
                    detail={
                        "import_id": imported.id,
                        "scan_id": imported.scan_id,
                        "findings": run.findings_count,
                    },
                    at=now,
                )
            else:
                imported.state = ImportState.FAILED
                imported.failure = end.failure or ImportFailure.UNREADABLE
                imported.failure_reason = end.reason
            return
        run.state = end.run_state
        run.failure = _RUN_FAILURE[end.failure]
        imported.state = ImportState.FAILED
        imported.failure = end.failure
        imported.failure_reason = end.reason
        if planned.state is ImportState.CHECKING:
            run.raw_parts = []
            drop_parts = True
        else:
            run.raw_parts = [f"{UPLOAD_PART}-{seq:05d}" for seq in range(1, planned.pieces + 1)]
    if drop_parts:
        service.raw_store.remove_parts(planned.scan_id, planned.run_id)
