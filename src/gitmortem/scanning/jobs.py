import functools
import os
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from sqlalchemy import select

from gitmortem import console
from gitmortem.config import BUILT_IN_TOOLS, guarded_key_file
from gitmortem.db.models import (
    DiscoveryRun,
    DiscoveryState,
    Repository,
    RepositoryKind,
    RepositoryVersion,
    ScanRoot,
    ToolRun,
    ToolRunFailure,
    ToolRunState,
    utcnow,
)
from gitmortem.explorer.access import RepoRead, Unavailable, checked_git_dir
from gitmortem.scanning.discovery import (
    DiscoveryCancelled,
    DiscoveryRecorder,
    Event,
    discover_and_inspect,
)
from gitmortem.scanning.options import run_options_model
from gitmortem.scanning.rule_patterns import StoredRule
from gitmortem.scanning.rules import stored_rules
from gitmortem.scanning.run import Progress
from gitmortem.scanning.store import record_results
from gitmortem.scanning.tools import Detection, ParsedFinding, RunContext, RunOutcome
from gitmortem.scanning.uow import read_only, unit_of_work
from gitmortem.uploads.place import uploads_dir

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from gitmortem.scanning.service import ScanService

WORK = "work"
RAW = "raw"
DISCOVERY_BATCH = 100
DISCOVERY_FLUSH_SECONDS = 1.0


@dataclass(frozen=True)
class ToolJob:
    KIND: ClassVar[str] = "tool run"
    id: int
    scan_id: int
    detection: Detection | None
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


@dataclass(frozen=True)
class RereadJob:
    KIND: ClassVar[str] = ToolJob.KIND
    id: int
    scan_id: int
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


@dataclass(frozen=True)
class DiscoveryJob:
    KIND: ClassVar[str] = "discovery"
    id: int
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


@dataclass(frozen=True)
class ImportJob:
    KIND: ClassVar[str] = "import"
    id: int
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


@dataclass(frozen=True)
class UploadJob:
    KIND: ClassVar[str] = "upload"
    id: int
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


@dataclass(frozen=True)
class DeletionJob:
    KIND: ClassVar[str] = "deletion"
    id: int
    cancel: threading.Event = field(default_factory=threading.Event, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.KIND, self.id)


Job = ToolJob | RereadJob | DiscoveryJob | ImportJob | UploadJob | DeletionJob
COUNTED_KINDS = frozenset({ToolJob.KIND, ImportJob.KIND, UploadJob.KIND})


def rechecked_git_dir(
    service: "ScanService", read: RepoRead | Unavailable, timeout: float
) -> Path | Unavailable:
    if isinstance(read, Unavailable):
        return read
    settings = service.settings
    return checked_git_dir(
        service.runner,
        read,
        bases=settings.scan_root_bases,
        data_dir=settings.data_dir,
        key_file=guarded_key_file(settings),
        deadline=time.monotonic() + timeout,
    )


def run_tool(service: "ScanService", job: ToolJob) -> None:
    progress = Progress()
    try:
        outcome = _run(service, job, progress)
    except Exception as exc:
        console.error(f"tool run {job.id} ended with an unexpected error ({type(exc).__name__})")
        progress.failed_with(exc)
        measured = progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_ERROR)
        stored = service.raw_store.parts(job.scan_id, job.id)
        outcome = replace(measured, raw_parts=tuple(sorted({*measured.raw_parts, *stored})))
    state = outcome.state
    if state is ToolRunState.CANCELLED and service.stopping:
        state = ToolRunState.INTERRUPTED
    with unit_of_work(service.engine) as session:
        run = session.scalars(
            select(ToolRun).where(ToolRun.id == job.id, ToolRun.state == ToolRunState.RUNNING)
        ).one_or_none()
        if run is None:
            return
        run.state = state
        run.failure = outcome.failure
        run.exit_code = outcome.exit_code
        run.integrity = outcome.integrity
        run.parse_issues = outcome.parse_issues
        run.raw_parts = list(outcome.raw_parts)
        run.parser_version = outcome.parser_version
        run.canary = outcome.canary
        run.canary_commit = outcome.canary_commit
        gaps = outcome.coverage_gaps
        run.coverage_gaps = None if gaps is None else gaps.model_dump()
        found = outcome.diagnosis
        run.diagnosis = None if found is None else found.model_dump(mode="json")
        run.finished_at = utcnow()


def _run(service: "ScanService", job: ToolJob, progress: Progress) -> RunOutcome:
    with read_only(service.engine) as session:
        tool, timeout, planned, repository_id, kind, deletion, git_dir, root, removed = (
            session.execute(
                select(
                    ToolRun.tool,
                    ToolRun.timeout_seconds,
                    ToolRun.options,
                    Repository.id,
                    Repository.kind,
                    Repository.deletion_state,
                    Repository.git_dir,
                    ScanRoot.path,
                    ScanRoot.removed_at,
                )
                .join(Repository, ToolRun.repository_id == Repository.id)
                .outerjoin(ScanRoot, Repository.scan_root_id == ScanRoot.id)
                .where(ToolRun.id == job.id)
            ).one()
        )
        versions = (
            tuple(
                Path(os.fsdecode(path))
                for path in session.scalars(
                    select(RepositoryVersion.git_dir)
                    .where(
                        RepositoryVersion.repository_id == repository_id,
                        RepositoryVersion.removed_at.is_(None),
                    )
                    .order_by(RepositoryVersion.current.desc(), RepositoryVersion.id.desc())
                )
            )
            if kind is RepositoryKind.UPLOADED
            else ()
        )
    spec = service.tools.get(tool)
    detection = job.detection
    no_file = detection is not None and detection.path is None and tool not in BUILT_IN_TOOLS
    if spec is None or detection is None or no_file or not detection.usable:
        return RunOutcome(ToolRunState.FAILED, failure=ToolRunFailure.TOOL_UNAVAILABLE)
    if deletion is not None or git_dir is None:
        return RunOutcome(ToolRunState.FAILED, failure=ToolRunFailure.REPOSITORY_UNAVAILABLE)
    uploaded = kind is RepositoryKind.UPLOADED
    if not uploaded and (root is None or removed is not None):
        return RunOutcome(ToolRunState.FAILED, failure=ToolRunFailure.OUTSIDE_ROOT)
    options = run_options_model(tool).model_validate(planned)
    settings = service.settings
    return spec.run(
        RunContext(
            runner=service.runner,
            git_dir=versions[0] if uploaded and versions else Path(os.fsdecode(git_dir)),
            root=uploads_dir(settings.data_dir) if uploaded else Path(root),
            bases=settings.scan_root_bases,
            data_dir=settings.data_dir,
            key_file=guarded_key_file(settings),
            work_dir=settings.data_dir / WORK,
            raw_store=service.raw_store,
            scan_id=job.scan_id,
            run_id=job.id,
            timeout=float(timeout),
            cancel=job.cancel,
            tool_path=detection.path,
            tool_sha256=detection.sha256,
            record=functools.partial(record_batch, service, job.id),
            progress=progress,
            options=options,
            rules=functools.partial(_load_rules, service),
            upload_root=uploads_dir(settings.data_dir) if uploaded else None,
            versions=versions,
        )
    )


def _load_rules(service: "ScanService", ids: Sequence[int]) -> list[StoredRule]:
    with read_only(service.engine) as session:
        return stored_rules(session, service.sealer, ids)


def record_batch(
    service: "ScanService",
    run_id: int,
    batch: Sequence[ParsedFinding],
    *,
    first_seen_at: datetime | None = None,
    imported: bool = False,
) -> None:
    with unit_of_work(service.engine) as session:
        run = session.scalars(select(ToolRun).where(ToolRun.id == run_id)).one()
        record_results(
            session, service.sealer, run, batch, first_seen_at=first_seen_at, imported=imported
        )


def run_discovery(service: "ScanService", job: DiscoveryJob) -> None:
    try:
        state = _discover(service, job)
    except DiscoveryCancelled:
        state = DiscoveryState.CANCELLED
    except Exception as exc:
        console.error(f"discovery {job.id} failed ({type(exc).__name__})")
        state = DiscoveryState.FAILED
    if state is DiscoveryState.DONE:
        return
    if state is DiscoveryState.CANCELLED and service.stopping:
        state = DiscoveryState.INTERRUPTED
    with unit_of_work(service.engine) as session:
        end_discovery(session, job.id, state)


def _discover(service: "ScanService", job: DiscoveryJob) -> DiscoveryState:
    with read_only(service.engine) as session:
        root_id, path, removed = session.execute(
            select(ScanRoot.id, ScanRoot.path, ScanRoot.removed_at)
            .join(DiscoveryRun, DiscoveryRun.scan_root_id == ScanRoot.id)
            .where(DiscoveryRun.id == job.id)
        ).one()
    if removed is not None or not service.root_is_usable(path):
        return DiscoveryState.FAILED
    recorder = DiscoveryRecorder(job.id, root_id)
    events = discover_and_inspect(
        service.runner, Path(path), skip=[service.settings.data_dir], cancel=job.cancel
    )
    for batch in batches(events):
        with unit_of_work(service.engine) as session:
            recorder.record(session, batch, now=utcnow())
    with unit_of_work(service.engine) as session:
        recorder.finish(session)
        end_discovery(session, job.id, DiscoveryState.DONE)
    return DiscoveryState.DONE


def end_discovery(session: "Session", discovery_id: int, state: DiscoveryState) -> None:
    run = session.scalars(
        select(DiscoveryRun).where(
            DiscoveryRun.id == discovery_id, DiscoveryRun.state == DiscoveryState.RUNNING
        )
    ).one_or_none()
    if run is not None:
        run.state = state
        run.finished_at = utcnow()


def batches(
    events: Iterable[Event],
    *,
    size: int = DISCOVERY_BATCH,
    seconds: float = DISCOVERY_FLUSH_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[list[Event]]:
    batch: list[Event] = []
    since = clock()
    for event in events:
        batch.append(event)
        if len(batch) >= size or clock() - since >= seconds:
            yield batch
            batch, since = [], clock()
    if batch:
        yield batch
