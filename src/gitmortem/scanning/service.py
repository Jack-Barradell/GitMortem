import threading
import time
from collections.abc import Collection, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

from sqlalchemy import ColumnElement, Engine, Select, and_, select, update
from sqlalchemy.orm import Session

from gitmortem import console
from gitmortem.config import Settings, guarded_key_file
from gitmortem.crypto import RawStore, Sealer
from gitmortem.db.models import (
    Deletion,
    DeletionJobState,
    DiscoveryRun,
    DiscoveryState,
    IntegrityState,
    Repository,
    RepositoryKind,
    RepositoryState,
    Scan,
    ScanKind,
    ScanRoot,
    ScanState,
    SkipReason,
    ToolName,
    ToolRun,
    ToolRunState,
    Upload,
    UploadState,
    utcnow,
)
from gitmortem.deletion import jobs as deletion_jobs
from gitmortem.gitrun import GitRunner
from gitmortem.scanning import import_jobs, imports, jobs, reread
from gitmortem.scanning.current import UNFINISHED_RUN, being_deleted
from gitmortem.scanning.jobs import (
    COUNTED_KINDS,
    RAW,
    WORK,
    DeletionJob,
    DiscoveryJob,
    ImportJob,
    Job,
    RereadJob,
    ToolJob,
    UploadJob,
)
from gitmortem.scanning.options import CustomRulesRun, no_rules, options_json
from gitmortem.scanning.registry import SCANNERS, TOOLS, detect_tools
from gitmortem.scanning.repos import Matching, RepositoryFilters, matching_scannable_ids
from gitmortem.scanning.roots import root_is_usable
from gitmortem.scanning.rules import enabled_rule_ids
from gitmortem.scanning.settings import (
    MAX_SCAN_WORKERS,
    ToolSettings,
    get_scan_workers,
    get_tool_options,
    get_tool_settings,
    repair_tool_options,
)
from gitmortem.scanning.tools import Detection, DetectionStatus, ToolSpec
from gitmortem.scanning.uow import read_only, unit_of_work
from gitmortem.trees import remove_tree
from gitmortem.uploads import jobs as upload_jobs
from gitmortem.uploads import records as upload_records
from gitmortem.uploads.apply import sweep_replaced
from gitmortem.uploads.pieces import UploadPieces
from gitmortem.uploads.place import pieces_dir, staging_dir

POLL_SECONDS = 0.5
SHUTDOWN_SECONDS = 30.0
_IDLE_CHECK_SECONDS = 0.05

UNFINISHED_SCAN = (ScanState.QUEUED, ScanState.RUNNING)
UNFINISHED_DISCOVERY = (DiscoveryState.QUEUED, DiscoveryState.RUNNING)

Key = tuple[str, int]


class Refusal(StrEnum):
    NOT_RUNNING = "not_running"
    NO_SUCH_ROOT = "no_such_root"
    ROOT_UNUSABLE = "root_unusable"
    DISCOVERY_RUNNING = "discovery_running"
    NOTHING_TO_SCAN = "nothing_to_scan"
    NO_SUCH_REPOSITORY = "no_such_repository"
    NOT_SCANNABLE = "not_scannable"
    REPOSITORY_ROOT_UNUSABLE = "repository_root_unusable"
    NO_TOOL_ENABLED = "no_tool_enabled"
    NO_SUCH_SCAN = "no_such_scan"
    SCAN_UNFINISHED = "scan_unfinished"
    NOT_ON_DISK = "not_on_disk"
    REPOSITORY_DELETED = "repository_deleted"


REFUSALS: dict[Refusal, str] = {
    Refusal.NOT_RUNNING: "Scanning is not running",
    Refusal.NO_SUCH_ROOT: "No such scan root",
    Refusal.ROOT_UNUSABLE: (
        "The scan root is gone, removed, or no longer inside a base the operator allowed"
    ),
    Refusal.DISCOVERY_RUNNING: "A discovery is already running for this scan root",
    Refusal.NOTHING_TO_SCAN: (
        "Nothing to scan: no repository was chosen, or the scan root has none that can be scanned"
    ),
    Refusal.NO_SUCH_REPOSITORY: "No such repository",
    Refusal.NOT_SCANNABLE: "The repository cannot be scanned: it is refused or missing",
    Refusal.REPOSITORY_ROOT_UNUSABLE: (
        "The repository's scan root is gone, removed, or no longer inside a base the operator "
        "allowed"
    ),
    Refusal.NO_TOOL_ENABLED: (
        "No scanner tool can run: none is enabled, or none of those enabled is detected, usable "
        "and has a rule turned on"
    ),
    Refusal.NO_SUCH_SCAN: "No such scan",
    Refusal.SCAN_UNFINISHED: "A run of the scan is still queued or running",
    Refusal.NOT_ON_DISK: (
        "The repository is not on this machine's disk: an import named it, and it is never scanned"
    ),
    Refusal.REPOSITORY_DELETED: "The repository is being deleted, or was deleted",
}


class ScanRefused(Exception):
    def __init__(self, reason: Refusal, about: int | str | None = None) -> None:
        text = REFUSALS[reason]
        super().__init__(f"{text}." if about is None else f"{text} ({about}).")
        self.reason = reason
        self.about = about


@dataclass(frozen=True)
class _Planned:
    name: ToolName
    settings: ToolSettings
    detection: Detection
    options: dict[str, object]


@dataclass(frozen=True)
class _Started:
    pool: ThreadPoolExecutor
    dispatcher: threading.Thread


class ScanService:
    def __init__(
        self,
        engine: Engine,
        instance_key: bytes,
        settings: Settings,
        *,
        runner: GitRunner,
        tools: Mapping[ToolName, ToolSpec] = TOOLS,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.runner = runner
        self.tools: Mapping[ToolName, ToolSpec] = MappingProxyType(dict(tools))
        self.sealer = Sealer(instance_key)
        self.raw_store = RawStore(settings.data_dir / RAW, instance_key)
        self.upload_pieces = UploadPieces(pieces_dir(settings.data_dir), instance_key)
        self._lock = threading.Lock()
        self._detections: dict[ToolName, Detection] = {}
        self._jobs: dict[Key, Job] = {}
        self._changed = threading.Condition()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._started: _Started | None = None
        self._next_expiry = 0.0

    @property
    def detections(self) -> Mapping[ToolName, Detection]:
        with self._lock:
            return MappingProxyType(dict(self._detections))

    def detect(self) -> Mapping[ToolName, Detection]:
        found = detect_tools(self.settings, self.runner, self.tools)
        with self._lock:
            self._detections = found
        return self.detections

    @property
    def running(self) -> bool:
        return self._started is not None and not self._stopping.is_set()

    @property
    def stopping(self) -> bool:
        return self._stopping.is_set()

    def recover(self) -> None:
        self.raw_store.sweep_temporaries()
        self.upload_pieces.sweep_temporaries()
        with unit_of_work(self.engine) as session:
            _finish_scans(session, utcnow())
            interrupt_unfinished(session, self.raw_store)
            repair_tool_options(session)
            import_jobs.requeue(session)
            upload_jobs.requeue(session, self)
            deletion_jobs.requeue(session)
        remove_tree(staging_dir(self.settings.data_dir), ignore_errors=True)
        upload_jobs.recover_folders(self.engine, self.settings.data_dir)
        sweep_replaced(self.engine, self.settings.data_dir)
        work = self.settings.data_dir / WORK
        if work.is_symlink() or (work.exists() and not work.is_dir()):
            work.unlink()
        elif work.exists():
            remove_tree(work)

    def start(self) -> None:
        if self._started is not None:
            raise RuntimeError("the scan service has already been started")
        pool = ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS, thread_name_prefix="gm-job")
        dispatcher = threading.Thread(
            target=self._loop, args=(pool,), name="gm-dispatcher", daemon=True
        )
        self._started = _Started(pool, dispatcher)
        dispatcher.start()

    def notify(self) -> None:
        self._wake.set()

    def wait_idle(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self._idle():
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            with self._changed:
                self._changed.wait(min(left, _IDLE_CHECK_SECONDS))
        return True

    def shutdown(self, timeout: float = SHUTDOWN_SECONDS) -> bool:
        deadline = time.monotonic() + timeout
        self._stopping.set()
        self._wake.set()
        started = self._started
        if started is None:
            return True
        started.dispatcher.join(max(0.0, deadline - time.monotonic()))
        with read_only(self.engine) as session:
            ended = list(session.scalars(_finishable().with_only_columns(Scan.id)))
        with self._lock:
            in_flight = list(self._jobs.values())
        for job in in_flight:
            job.cancel.set()
        stopped = self.wait_idle(max(0.0, deadline - time.monotonic()))
        stopped = stopped and not started.dispatcher.is_alive()
        started.pool.shutdown(wait=stopped, cancel_futures=True)
        with unit_of_work(self.engine) as session:
            _finish_scans(session, utcnow(), only=ended)
            interrupt_unfinished(session, self.raw_store)
        return stopped

    def plan_discovery(self, session: Session, root_id: int, user_id: int | None) -> int:
        self._require_running()
        root = session.get(ScanRoot, root_id)
        if root is None or root.removed_at is not None:
            raise ScanRefused(Refusal.NO_SUCH_ROOT)
        if not self.root_is_usable(root.path):
            raise ScanRefused(Refusal.ROOT_UNUSABLE)
        busy = session.scalar(
            select(DiscoveryRun.id)
            .where(
                DiscoveryRun.scan_root_id == root_id,
                DiscoveryRun.state.in_(UNFINISHED_DISCOVERY),
            )
            .limit(1)
        )
        if busy is not None:
            raise ScanRefused(Refusal.DISCOVERY_RUNNING)
        run = DiscoveryRun(
            scan_root_id=root_id,
            started_by_user_id=user_id,
            state=DiscoveryState.QUEUED,
            created_at=utcnow(),
        )
        session.add(run)
        session.flush()
        return run.id

    def plan_scan(
        self,
        session: Session,
        repository_ids: Sequence[int],
        user_id: int | None,
        *,
        root_ids: Sequence[int] = (),
        matching: Matching | None = None,
    ) -> int:
        self._require_running()
        named = list(dict.fromkeys(repository_ids))
        roots = list(dict.fromkeys(root_ids))
        if not named and not roots and matching is None:
            raise ScanRefused(Refusal.NOTHING_TO_SCAN)
        usable: dict[int, bool] = {}
        for repo_id in named:
            self._check_repository(session, repo_id, usable)
        found = [
            repo_id
            for root_id in roots
            for repo_id in self._root_repositories(session, root_id, usable)
        ]
        if matching is not None:
            found += self._matching_repositories(session, matching, usable)
        wanted = list(dict.fromkeys(named + found))
        tools, skipped = self._enabled_tools(session)
        scan = Scan(
            state=ScanState.QUEUED,
            workers=get_scan_workers(session),
            started_by_user_id=user_id,
            created_at=utcnow(),
            skipped_tools={name.value: reason.value for name, reason in skipped.items()},
        )
        session.add(scan)
        session.flush()
        for repo_id in wanted:
            for tool in tools:
                session.add(
                    ToolRun(
                        scan_id=scan.id,
                        repository_id=repo_id,
                        tool=tool.name,
                        identity=tool.detection.identity or tool.name.value,
                        binary_sha256=tool.detection.sha256,
                        state=ToolRunState.QUEUED,
                        integrity=IntegrityState.NOT_CHECKED,
                        timeout_seconds=tool.settings.timeout_seconds,
                        options=tool.options,
                    )
                )
        session.flush()
        return scan.id

    def plan_reread(
        self, session: Session, user_id: int | None, *, scan_id: int | None, stale: bool
    ) -> reread.RereadPlan:
        self._require_running()
        if scan_id is not None:
            if session.get(Scan, scan_id) is None:
                raise ScanRefused(Refusal.NO_SUCH_SCAN)
            if _has_unfinished_runs(session, scan_id):
                raise ScanRefused(Refusal.SCAN_UNFINISHED)
        return reread.plan_reread(session, user_id, scan_id=scan_id, stale=stale, tools=self.tools)

    def request_cancel(self, session: Session, job: Scan | DiscoveryRun) -> bool:
        unfinished = UNFINISHED_SCAN if isinstance(job, Scan) else UNFINISHED_DISCOVERY
        if job.state not in unfinished:
            return False
        if isinstance(job, Scan) and not _has_unfinished_runs(session, job.id):
            _finish(session, job, utcnow())
            session.flush()
            return False
        if job.cancel_requested_at is None:
            job.cancel_requested_at = utcnow()
            session.flush()
        return True

    def root_is_usable(self, path: str) -> bool:
        return root_is_usable(
            path,
            bases=self.settings.scan_root_bases,
            data_dir=self.settings.data_dir,
            key_file=guarded_key_file(self.settings),
        )

    def _require_running(self) -> None:
        if not self.running:
            raise ScanRefused(Refusal.NOT_RUNNING)

    def _check_repository(self, session: Session, repo_id: int, usable: dict[int, bool]) -> None:
        repo = session.get(Repository, repo_id)
        if repo is None:
            raise ScanRefused(Refusal.NO_SUCH_REPOSITORY, repo_id)
        if repo.deletion_state is not None:
            raise ScanRefused(Refusal.REPOSITORY_DELETED, repo_id)
        if (
            repo.state is not RepositoryState.SCANNABLE
            and repo.kind is not RepositoryKind.NOT_ON_DISK
        ):
            raise ScanRefused(Refusal.NOT_SCANNABLE, repo_id)
        if repo.kind is RepositoryKind.UPLOADED:
            return
        root_id = repo.scan_root_id
        if repo.kind is RepositoryKind.NOT_ON_DISK or root_id is None:
            raise ScanRefused(Refusal.NOT_ON_DISK, repo_id)
        if root_id not in usable:
            root = session.get(ScanRoot, root_id)
            usable[root_id] = (
                root is not None and root.removed_at is None and self.root_is_usable(root.path)
            )
        if not usable[root_id]:
            raise ScanRefused(Refusal.REPOSITORY_ROOT_UNUSABLE, repo_id)

    def _matching_repositories(
        self, session: Session, matching: Matching, usable: dict[int, bool]
    ) -> list[int]:
        excluded = set(matching.excluded)
        chosen = [
            repo_id
            for repo_id in self._root_repositories(
                session, matching.root_id, usable, matching.filters, allow_empty=True
            )
            if repo_id not in excluded
        ]
        for repo_id in matching.included:
            self._check_repository(session, repo_id, usable)
        picked = list(dict.fromkeys([*chosen, *matching.included]))
        if not picked:
            raise ScanRefused(Refusal.NOTHING_TO_SCAN, matching.root_id)
        return picked

    def _root_repositories(
        self,
        session: Session,
        root_id: int,
        usable: dict[int, bool],
        filters: RepositoryFilters | None = None,
        *,
        allow_empty: bool = False,
    ) -> list[int]:
        root = session.get(ScanRoot, root_id)
        if root is None or root.removed_at is not None:
            raise ScanRefused(Refusal.NO_SUCH_ROOT, root_id)
        if root_id not in usable:
            usable[root_id] = self.root_is_usable(root.path)
        if not usable[root_id]:
            raise ScanRefused(Refusal.ROOT_UNUSABLE, root_id)
        if filters is not None:
            found = matching_scannable_ids(session, root_id, filters)
            if not found and not allow_empty:
                raise ScanRefused(Refusal.NOTHING_TO_SCAN, root_id)
            return found
        found = list(
            session.scalars(
                select(Repository.id)
                .where(
                    Repository.scan_root_id == root_id,
                    Repository.state == RepositoryState.SCANNABLE,
                    Repository.deletion_state.is_(None),
                )
                .order_by(Repository.id)
            )
        )
        if not found:
            raise ScanRefused(Refusal.NOTHING_TO_SCAN, root_id)
        return found

    def _enabled_tools(self, session: Session) -> tuple[list[_Planned], dict[ToolName, SkipReason]]:
        detections = self.detections
        planned: list[_Planned] = []
        skipped: dict[ToolName, SkipReason] = {}
        for name in dict.fromkeys([*SCANNERS, *self.tools]):
            settings = get_tool_settings(session, name)
            if not settings.enabled:
                continue
            detection = detections.get(name) if name in self.tools else None
            if detection is None or not detection.usable:
                unsupported = detection is not None and (
                    detection.status is DetectionStatus.UNSUPPORTED
                )
                skipped[name] = SkipReason.UNSUPPORTED if unsupported else SkipReason.UNAVAILABLE
                continue
            options = get_tool_options(session, name)
            if name is ToolName.CUSTOM_RULES:
                options = CustomRulesRun(rules=tuple(enabled_rule_ids(session)))
            if no_rules(options):
                skipped[name] = SkipReason.NO_RULES
                continue
            planned.append(_Planned(name, settings, detection, options_json(options)))
        if not planned:
            raise ScanRefused(Refusal.NO_TOOL_ENABLED)
        return planned, skipped

    def _loop(self, pool: ThreadPoolExecutor) -> None:
        failing = False
        while not self._stopping.is_set():
            self._wake.clear()
            try:
                self._dispatch(pool)
            except Exception as exc:
                if not failing:
                    console.error(f"a scan dispatch failed ({type(exc).__name__}); trying again")
                failing = True
            else:
                if failing:
                    console.ok("scan dispatch is working again")
                failing = False
            with self._changed:
                self._changed.notify_all()
            self._wake.wait(POLL_SECONDS)

    def _dispatch(self, pool: ThreadPoolExecutor) -> None:
        if self._stopping.is_set():
            return
        self._expire()
        if not self._has_work():
            return
        started: list[Job] = []
        try:
            with unit_of_work(self.engine) as session:
                now = utcnow()
                self._apply_cancels(session, now)
                self._end_orphans(session, now)
                started = self._take(session, now)
                finished = _finish_scans(session, now)
        except BaseException:
            with self._lock:
                for job in started:
                    self._jobs.pop(job.key, None)
            raise
        for job in started:
            pool.submit(self._work, job)
        if finished:
            sweep_replaced(self.engine, self.settings.data_dir)

    def _expire(self) -> None:
        if time.monotonic() < self._next_expiry:
            return
        self._next_expiry = time.monotonic() + imports.EXPIRY_SECONDS
        with unit_of_work(self.engine) as session:
            imports.expire_imports(session, self.raw_store, utcnow())
            upload_records.expire_uploads(
                session, self.upload_pieces, self.settings.data_dir, utcnow()
            )
        sweep_replaced(self.engine, self.settings.data_dir)

    def _held(self) -> set[Key]:
        with self._lock:
            return set(self._jobs)

    def _has_work(self) -> bool:
        held = self._held()
        free = MAX_SCAN_WORKERS - len(held)
        counted = sum(1 for kind, _ in held if kind in COUNTED_KINDS)
        importing = [row_id for kind, row_id in held if kind == ImportJob.KIND]
        with read_only(self.engine) as session:
            if any(key not in held for key in _running(session)):
                return True
            for query in (_scans_to_cancel(), _discoveries_to_cancel(), _finishable()):
                if session.scalar(query.limit(1)) is not None:
                    return True
            if free > 0 and session.scalar(_queued_discoveries().limit(1)) is not None:
                return True
            deleting = any(k == DeletionJob.KIND for k, _ in held)
            if free > 0 and deletion_jobs.has_due(session, held=deleting):
                return True
            room = min(free, get_scan_workers(session) - counted)
            if room <= 0:
                return False
            if import_jobs.has_due(session, importing):
                return True
            if upload_jobs.has_due(session, held=any(k == UploadJob.KIND for k, _ in held)):
                return True
            return session.scalar(_queued_runs().limit(1)) is not None

    def stop_runs(self, run_ids: Collection[int]) -> None:
        for run_id in run_ids:
            self._cancel((ToolJob.KIND, run_id))

    def stop_upload(self, upload_id: int) -> None:
        self._cancel((UploadJob.KIND, upload_id))

    def stop_imports(self, import_ids: Collection[int]) -> None:
        for import_id in import_ids:
            self._cancel((ImportJob.KIND, import_id))

    def holds_imports(self, import_ids: Collection[int]) -> bool:
        held = self._held()
        return any((ImportJob.KIND, import_id) in held for import_id in import_ids)

    def _cancel(self, key: Key) -> None:
        with self._lock:
            job = self._jobs.get(key)
        if job is not None:
            job.cancel.set()

    def _apply_cancels(self, session: Session, now: datetime) -> None:
        cancelled = select(Scan.id).where(
            Scan.state.in_(UNFINISHED_SCAN), Scan.cancel_requested_at.is_not(None), _not_import()
        )
        session.execute(
            update(ToolRun)
            .where(ToolRun.scan_id.in_(cancelled), ToolRun.state == ToolRunState.QUEUED)
            .values(state=ToolRunState.CANCELLED, finished_at=now)
            .execution_options(synchronize_session=False)
        )
        running = session.scalars(
            select(ToolRun.id).where(
                ToolRun.scan_id.in_(cancelled), ToolRun.state == ToolRunState.RUNNING
            )
        )
        for run_id in running:
            self._cancel((ToolJob.KIND, run_id))
        for discovery in session.scalars(_discoveries_to_cancel()).all():
            if discovery.state is DiscoveryState.QUEUED:
                discovery.state = DiscoveryState.CANCELLED
                discovery.finished_at = now
            else:
                self._cancel((DiscoveryJob.KIND, discovery.id))

    def _end_orphans(self, session: Session, now: datetime) -> None:
        running = _running(session)
        held = self._held()
        orphans = [key for key in running if key not in held]
        runs = [row_id for kind, row_id in orphans if kind == ToolJob.KIND]
        discoveries = [row_id for kind, row_id in orphans if kind == DiscoveryJob.KIND]
        _interrupt_runs(session, self.raw_store, ToolRun.id.in_(runs), now)
        session.execute(
            update(DiscoveryRun)
            .where(DiscoveryRun.id.in_(discoveries))
            .values(state=DiscoveryState.INTERRUPTED, finished_at=now)
            .execution_options(synchronize_session=False)
        )

    def _take(self, session: Session, now: datetime) -> list[Job]:
        held = self._held()
        free = MAX_SCAN_WORKERS - len(held)
        counted = sum(1 for kind, _ in held if kind in COUNTED_KINDS)
        importing = [row_id for kind, row_id in held if kind == ImportJob.KIND]
        taken: list[Job] = []
        for discovery in session.scalars(_queued_discoveries().limit(free)).all():
            discovery.state = DiscoveryState.RUNNING
            discovery.started_at = now
            taken.append(DiscoveryJob(discovery.id))
        room = min(free - len(taken), get_scan_workers(session) - counted)
        for import_id in import_jobs.take_imports(session, now, limit=max(room, 0), held=importing):
            taken.append(ImportJob(import_id))
            room -= 1
        deleting = any(kind == DeletionJob.KIND for kind, _ in held)
        if free - len(taken) > 0:
            for deletion_id in deletion_jobs.take_deletions(session, held=deleting):
                taken.append(DeletionJob(deletion_id))
        uploading = any(kind == UploadJob.KIND for kind, _ in held)
        if room > 0:
            for upload_id in upload_jobs.take_uploads(session, held=uploading):
                taken.append(UploadJob(upload_id))
                room -= 1
        if room > 0:
            detections = self.detections
            runs = session.scalars(_queued_runs().limit(room)).all()
            for run in runs:
                run.state = ToolRunState.RUNNING
                run.started_at = now
                if run.reread_of_id is not None:
                    taken.append(RereadJob(run.id, scan_id=run.scan_id))
                    continue
                detection = detections.get(run.tool)
                if detection is not None and detection.identity is not None:
                    run.identity = detection.identity
                taken.append(ToolJob(run.id, scan_id=run.scan_id, detection=detection))
            session.execute(
                update(Scan)
                .where(Scan.id.in_({run.scan_id for run in runs}), Scan.state == ScanState.QUEUED)
                .values(state=ScanState.RUNNING, started_at=now)
                .execution_options(synchronize_session=False)
            )
        session.flush()
        with self._lock:
            for job in taken:
                self._jobs[job.key] = job
        return taken

    def _work(self, job: Job) -> None:
        try:
            if isinstance(job, RereadJob):
                reread.run_reread(self, job)
            elif isinstance(job, ToolJob):
                jobs.run_tool(self, job)
            elif isinstance(job, ImportJob):
                import_jobs.run_import(self, job)
            elif isinstance(job, UploadJob):
                upload_jobs.run_upload(self, job)
            elif isinstance(job, DeletionJob):
                deletion_jobs.run_deletion(self, job)
            else:
                jobs.run_discovery(self, job)
        except Exception as exc:
            console.error(f"{job.KIND} {job.id} could not record its end ({type(exc).__name__})")
        finally:
            with self._lock:
                self._jobs.pop(job.key, None)
            self._wake.set()
            with self._changed:
                self._changed.notify_all()

    def _idle(self) -> bool:
        with self._lock:
            if self._jobs:
                return False
        if not self.running:
            return True
        with read_only(self.engine) as session:
            if session.scalar(
                select(Upload.id)
                .where(Upload.state.in_((UploadState.QUEUED, UploadState.PROCESSING)))
                .limit(1)
            ):
                return False
            if session.scalar(
                select(Deletion.id)
                .where(Deletion.state.in_((DeletionJobState.QUEUED, DeletionJobState.RUNNING)))
                .limit(1)
            ):
                return False
            return not import_jobs.has_due(session, ()) and all(
                session.scalar(query.limit(1)) is None
                for query in (
                    select(ToolRun.id).where(ToolRun.state.in_(UNFINISHED_RUN), _not_imports()),
                    select(DiscoveryRun.id).where(DiscoveryRun.state.in_(UNFINISHED_DISCOVERY)),
                    select(Scan.id).where(Scan.state.in_(UNFINISHED_SCAN), _not_import()),
                )
            )


def _not_import() -> ColumnElement[bool]:
    return Scan.kind != ScanKind.IMPORT


def _not_imports() -> ColumnElement[bool]:
    return ToolRun.scan_id.not_in(select(Scan.id).where(Scan.kind == ScanKind.IMPORT))


def interrupt_unfinished(session: Session, raw_store: RawStore) -> None:
    now = utcnow()
    _interrupt_runs(
        session, raw_store, and_(ToolRun.state.in_(UNFINISHED_RUN), _not_imports()), now
    )
    session.execute(
        update(DiscoveryRun)
        .where(DiscoveryRun.state.in_(UNFINISHED_DISCOVERY))
        .values(state=DiscoveryState.INTERRUPTED, finished_at=now)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(Scan)
        .where(
            Scan.state.in_(UNFINISHED_SCAN), Scan.cancel_requested_at.is_not(None), _not_import()
        )
        .values(state=ScanState.CANCELLED, finished_at=now)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(Scan)
        .where(Scan.state.in_(UNFINISHED_SCAN), _not_import())
        .values(state=ScanState.INTERRUPTED, finished_at=now)
        .execution_options(synchronize_session=False)
    )


def _interrupt_runs(
    session: Session, raw_store: RawStore, which: ColumnElement[bool], now: datetime
) -> None:
    running = session.execute(
        select(ToolRun.id, ToolRun.scan_id).where(which, ToolRun.state == ToolRunState.RUNNING)
    ).all()
    for run_id, scan_id in running:
        try:
            parts = list(raw_store.parts(scan_id, run_id))
        except OSError as exc:
            console.error(
                f"tool run {run_id} of scan {scan_id}: its raw parts could not be listed "
                f"({type(exc).__name__}); none are recorded"
            )
            parts = []
        session.execute(
            update(ToolRun)
            .where(ToolRun.id == run_id)
            .values(state=ToolRunState.INTERRUPTED, finished_at=now, raw_parts=parts)
            .execution_options(synchronize_session=False)
        )
    session.execute(
        update(ToolRun)
        .where(which, ToolRun.state.in_(UNFINISHED_RUN))
        .values(state=ToolRunState.INTERRUPTED, finished_at=now)
        .execution_options(synchronize_session=False)
    )


def _running(session: Session) -> list[Key]:
    runs = session.scalars(
        select(ToolRun.id).where(ToolRun.state == ToolRunState.RUNNING, _not_imports())
    )
    found: list[Key] = [(ToolJob.KIND, run_id) for run_id in runs]
    discoveries = session.scalars(
        select(DiscoveryRun.id).where(DiscoveryRun.state == DiscoveryState.RUNNING)
    )
    found += [(DiscoveryJob.KIND, discovery_id) for discovery_id in discoveries]
    return found


def _scans_to_cancel() -> Select[Scan]:
    return select(Scan).where(
        Scan.state.in_(UNFINISHED_SCAN), Scan.cancel_requested_at.is_not(None), _not_import()
    )


def _discoveries_to_cancel() -> Select[DiscoveryRun]:
    return select(DiscoveryRun).where(
        DiscoveryRun.state.in_(UNFINISHED_DISCOVERY),
        DiscoveryRun.cancel_requested_at.is_not(None),
    )


def _queued_discoveries() -> Select[DiscoveryRun]:
    return (
        select(DiscoveryRun)
        .where(
            DiscoveryRun.state == DiscoveryState.QUEUED,
            DiscoveryRun.cancel_requested_at.is_(None),
        )
        .order_by(DiscoveryRun.id)
    )


def _queued_runs() -> Select[ToolRun]:
    return (
        select(ToolRun)
        .join(Scan, ToolRun.scan_id == Scan.id)
        .where(
            ToolRun.state == ToolRunState.QUEUED,
            Scan.cancel_requested_at.is_(None),
            _not_import(),
            ToolRun.repository_id.not_in(being_deleted()),
        )
        .order_by(ToolRun.id)
    )


def _finishable() -> Select[Scan]:
    pending = (
        select(ToolRun.id)
        .where(ToolRun.scan_id == Scan.id, ToolRun.state.in_(UNFINISHED_RUN))
        .exists()
    )
    return select(Scan).where(Scan.state.in_(UNFINISHED_SCAN), ~pending, _not_import())


def _finish_scans(session: Session, now: datetime, *, only: Collection[int] | None = None) -> int:
    query = _finishable() if only is None else _finishable().where(Scan.id.in_(only))
    scans = session.scalars(query).all()
    for scan in scans:
        _finish(session, scan, now)
    return len(scans)


def _finish(session: Session, scan: Scan, now: datetime) -> None:
    if scan.cancel_requested_at is not None:
        scan.state = ScanState.CANCELLED
    elif _has_interrupted_run(session, scan.id):
        scan.state = ScanState.INTERRUPTED
    else:
        scan.state = ScanState.FINISHED
    scan.finished_at = now


def _has_interrupted_run(session: Session, scan_id: int) -> bool:
    found = select(ToolRun.id).where(
        ToolRun.scan_id == scan_id,
        ToolRun.state == ToolRunState.INTERRUPTED,
        ToolRun.kept_end.is_(False),
    )
    return session.scalar(found.limit(1)) is not None


def _has_unfinished_runs(session: Session, scan_id: int) -> bool:
    return _has_runs_in(session, scan_id, UNFINISHED_RUN)


def _has_runs_in(session: Session, scan_id: int, states: Collection[ToolRunState]) -> bool:
    found = select(ToolRun.id).where(ToolRun.scan_id == scan_id, ToolRun.state.in_(states))
    return session.scalar(found.limit(1)) is not None
