import contextlib
import io
import os
import re
import shutil
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, cast

from sqlalchemy import select

from gitmortem import console
from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import (
    AuditValue,
    Repository,
    RepositoryVersion,
    Upload,
    UploadFailure,
    UploadRepo,
    UploadRepoOutcome,
    UploadRepoRefusal,
    UploadState,
    utcnow,
)
from gitmortem.gitrun import GitCancelled, GitError
from gitmortem.scanning.settings import UploadLimits, get_upload_limits
from gitmortem.scanning.uow import read_only, retry_busy, unit_of_work
from gitmortem.trees import remove_tree
from gitmortem.uploads.apply import apply, sweep_replaced
from gitmortem.uploads.extract import ExtractCancelled, Extracted, extract_git_dir
from gitmortem.uploads.found import (
    GIT_FILE_BYTES,
    FoundRepo,
    find_repos,
    is_git_entry,
    owned_entries,
    shown_path,
)
from gitmortem.uploads.matching import (
    Ask,
    Decision,
    New,
    Update,
    decide,
    known_for,
    lacks_anything,
    resolve_conflicts,
)
from gitmortem.uploads.pieces import PieceStoreUnreachable, PieceUnreadable, SealedZipReader
from gitmortem.uploads.place import (
    DISK_RESERVE_BYTES,
    new_pending_dir,
    new_version_dir,
    pending_dir,
    private_folder,
    repos_dir,
    staging_dir,
    uploads_dir,
)
from gitmortem.uploads.rebuild import Rebuilt, rebuild
from gitmortem.uploads.records import pieces_of
from gitmortem.uploads.ziplist import ZipEntry, ZipRefused, list_zip, read_small

if TYPE_CHECKING:
    from sqlalchemy import Engine
    from sqlalchemy.orm import Session

    from gitmortem.scanning.jobs import UploadJob
    from gitmortem.scanning.service import ScanService

REPO_SECONDS = 3600.0


class _Failed(Exception):
    def __init__(self, failure: UploadFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


@dataclass
class _Pass:
    new: int = 0
    replaced: int = 0
    new_version: int = 0
    waiting: int = 0
    refused: int = 0


MAX_INTERRUPTED_RUNS = 2
_TOKEN_FOLDER = re.compile(r"[0-9a-f]{32}\.git")


def _discarded(session: "Session", upload_id: int) -> bool:
    state = session.scalar(select(Upload.state).where(Upload.id == upload_id))
    return state is UploadState.DISCARDED


def _again_or_failed(service: "ScanService", upload_id: int) -> None:
    def decide(session: "Session") -> bool:
        upload = session.get(Upload, upload_id)
        if upload is None or upload.state is not UploadState.PROCESSING:
            return False
        upload.interrupted_runs += 1
        if upload.interrupted_runs <= MAX_INTERRUPTED_RUNS:
            upload.state = UploadState.QUEUED
            return False
        upload.state, upload.failure = UploadState.FAILED, UploadFailure.UNEXPECTED_ERROR
        upload.finished_at = utcnow()
        return True

    if retry_busy(service.engine, decide):
        service.upload_pieces.remove(upload_id)
        _forget_pending(service, upload_id)


def recover_folders(engine: "Engine", data_dir: Path) -> None:
    with read_only(engine) as session:
        placing = [
            (row.id, Path(os.fsdecode(row.placing_dir)), row.pending_dir)
            for row in session.scalars(
                select(UploadRepo).where(UploadRepo.placing_dir.is_not(None))
            )
            if row.placing_dir is not None
        ]
        versions = _names(session.scalars(select(RepositoryVersion.git_dir)))
    for row_id, place, pending in placing:
        if place.name not in versions:
            held = None if pending is None else Path(os.fsdecode(pending))
            if held is not None and not os.path.lexists(held) and os.path.isdir(place):
                private_folder(held.parent)
                os.replace(place, held)
            else:
                _remove(place)

        def cleared(session: "Session", row_id: int = row_id) -> None:
            row = session.get(UploadRepo, row_id)
            if row is not None:
                row.placing_dir = None

        retry_busy(engine, cleared)
    with read_only(engine) as session:
        versions = _names(session.scalars(select(RepositoryVersion.git_dir)))
        waiting = _names(
            session.scalars(
                select(UploadRepo.pending_dir).where(UploadRepo.pending_dir.is_not(None))
            )
        )
    _sweep_unnamed(repos_dir(data_dir), versions)
    _sweep_unnamed(pending_dir(data_dir), waiting)


def _names(stored: Iterable[bytes | None]) -> set[str]:
    return {Path(os.fsdecode(raw)).name for raw in stored if raw is not None}


def _remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        remove_tree(path, ignore_errors=True)


def _sweep_unnamed(root: Path, named: set[str]) -> None:
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for entry in entries:
        path = Path(entry.path)
        if entry.is_symlink():
            path.unlink(missing_ok=True)
        elif _TOKEN_FOLDER.fullmatch(entry.name) and entry.name not in named:
            _remove(path)


def take_uploads(session: "Session", *, held: bool) -> list[int]:
    if held:
        return []
    found = session.scalars(
        select(Upload).where(Upload.state == UploadState.QUEUED).order_by(Upload.id).limit(1)
    ).first()
    if found is None:
        return []
    found.state = UploadState.PROCESSING
    session.flush()
    return [found.id]


def has_due(session: "Session", *, held: bool) -> bool:
    if held:
        return False
    return (
        session.scalar(select(Upload.id).where(Upload.state == UploadState.QUEUED).limit(1))
        is not None
    )


def requeue(session: "Session", service: "ScanService") -> None:
    for upload in session.scalars(select(Upload).where(Upload.state == UploadState.PROCESSING)):
        answered = session.scalar(
            select(UploadRepo.id).where(
                UploadRepo.upload_id == upload.id,
                UploadRepo.outcome == UploadRepoOutcome.ANSWERED,
            )
        )
        whole = service.upload_pieces.count(upload.id) == pieces_of(upload.size_bytes)
        outcomes = set(
            session.scalars(select(UploadRepo.outcome).where(UploadRepo.upload_id == upload.id))
        )
        settled = bool(outcomes) and UploadRepoOutcome.PENDING not in outcomes
        upload.interrupted_runs += 1
        resumable = whole or answered is not None or settled
        if resumable and upload.interrupted_runs <= MAX_INTERRUPTED_RUNS:
            upload.state = UploadState.QUEUED
        else:
            upload.state = UploadState.FAILED
            upload.failure = UploadFailure.INTERRUPTED
            upload.finished_at = utcnow()
    session.flush()


def run_upload(service: "ScanService", job: "UploadJob") -> None:
    data_dir = service.settings.data_dir
    done = _Pass()
    try:
        with read_only(service.engine) as session:
            upload = session.get(Upload, job.id)
            if upload is None:
                return
            size, client_name, org_prefix = upload.size_bytes, upload.client_name, upload.org_prefix
            user_id = upload.created_by_user_id
            limits = get_upload_limits(session)
            unpacked = (
                session.scalars(
                    select(UploadRepo.id).where(UploadRepo.upload_id == job.id).limit(1)
                ).first()
                is not None
            )
        if service.upload_pieces.count(job.id) == pieces_of(size):
            _unpack(service, job, size, client_name, org_prefix, user_id, limits, done)
        elif not unpacked:
            raise _Failed(UploadFailure.PIECES_UNREADABLE)
        _apply_answered(service, job, user_id, done)
        service.upload_pieces.remove(job.id)
        remove_tree(staging_dir(data_dir) / str(job.id), ignore_errors=True)
        _end(service, job, done, user_id, failure=None)
    except (ExtractCancelled, GitCancelled):
        remove_tree(staging_dir(data_dir) / str(job.id), ignore_errors=True)
        with read_only(service.engine) as session:
            discarded = _discarded(session, job.id)
        if discarded:
            _after_discard(service, job.id, user_id)
    except PieceStoreUnreachable:
        remove_tree(staging_dir(data_dir) / str(job.id), ignore_errors=True)
        _again_or_failed(service, job.id)
    except _Failed as failed:
        _end(service, job, done, user_id, failure=failed.failure)
    except Exception as exc:
        console.error(f"upload {job.id} failed ({type(exc).__name__})")
        _end(service, job, done, user_id, failure=UploadFailure.UNEXPECTED_ERROR)


def _unpack(
    service: "ScanService",
    job: "UploadJob",
    size: int,
    client_name: str,
    org_prefix: str | None,
    user_id: int | None,
    limits: UploadLimits,
    done: _Pass,
) -> None:
    data_dir = service.settings.data_dir
    reader = cast(
        BinaryIO, io.BufferedReader(SealedZipReader(service.upload_pieces, job.id, size), 1 << 20)
    )
    try:
        listing = list_zip(reader, size, limits, is_git_entry)
        found = find_repos(
            listing,
            lambda entry: read_small(reader, entry, GIT_FILE_BYTES),
            client_name=client_name,
            org_prefix=org_prefix,
        )
    except ZipRefused as refused:
        raise _Failed(UploadFailure(refused.reason.value)) from None
    except PieceUnreadable:
        raise _Failed(UploadFailure.PIECES_UNREADABLE) from None
    if not found.repos and not found.refused:
        raise _Failed(UploadFailure.NO_REPOS)
    git_bytes = sum(e.size for e in listing.entries)
    if shutil.disk_usage(data_dir).free < 2 * git_bytes + DISK_RESERVE_BYTES:
        raise _Failed(UploadFailure.DISK_FULL)
    stale: list[Path] = []
    with unit_of_work(service.engine) as session:
        now = utcnow()
        settled = _settled_before(session, job.id, stale)
        for refusal in found.refused:
            if (shown_path(refusal.zip_path) or client_name) in settled:
                continue
            session.add(
                UploadRepo(
                    upload_id=job.id,
                    zip_path=shown_path(refusal.zip_path) or client_name,
                    name=shown_path(refusal.zip_path).rpartition("/")[2] or client_name,
                    outcome=UploadRepoOutcome.REFUSED,
                    refusal=refusal.refusal,
                    created_at=now,
                )
            )
            done.refused += 1
        rows = []
        repos = [repo for repo in found.repos if (repo.shown_path or client_name) not in settled]
        for repo in repos:
            row = UploadRepo(
                upload_id=job.id,
                zip_path=repo.shown_path or client_name,
                org=repo.org,
                name=repo.name,
                outcome=UploadRepoOutcome.PENDING,
                created_at=now,
            )
            session.add(row)
            rows.append(row)
        session.flush()
        row_ids = [row.id for row in rows]
    area = uploads_dir(data_dir).resolve()
    for folder in stale:
        if not folder.is_symlink() and folder.resolve().is_relative_to(area):
            _remove(folder)
    staged = staging_dir(data_dir) / str(job.id)
    private_folder(staged)
    rebuilt: list[tuple[int, FoundRepo, Rebuilt]] = []
    owned = owned_entries(listing, found.repos)
    for number, (row_id, repo) in enumerate(zip(row_ids, repos, strict=True)):
        deadline = time.monotonic() + REPO_SECONDS
        made = _rebuilt(
            service,
            job,
            reader,
            owned[repo.git_prefix],
            repo,
            staged / str(number),
            limits,
            deadline,
        )
        if isinstance(made, Rebuilt):
            rebuilt.append((row_id, repo, made))
            continue
        with unit_of_work(service.engine) as session:
            refused_row = session.get(UploadRepo, row_id)
            if refused_row is not None:
                refused_row.outcome, refused_row.refusal = UploadRepoOutcome.REFUSED, made
        done.refused += 1
    with read_only(service.engine) as session:
        known = [known_for(session, repo) for _row_id, repo, _made in rebuilt]
    decisions = resolve_conflicts(
        [
            decide(
                service.runner,
                repo,
                made,
                facts,
                scratch=staged / f"scratch-{row_id}",
                deadline=time.monotonic() + REPO_SECONDS,
                cancel=job.cancel,
            )
            for (row_id, repo, made), facts in zip(rebuilt, known, strict=True)
        ]
    )
    for (row_id, _repo, made), decision in zip(rebuilt, decisions, strict=True):
        _settle(service, row_id, made, decision, user_id, done)


def _settled_before(session: "Session", upload_id: int, stale: list[Path]) -> set[str]:
    settled: set[str] = set()
    for row in session.scalars(select(UploadRepo).where(UploadRepo.upload_id == upload_id)):
        if row.outcome is not UploadRepoOutcome.PENDING:
            settled.add(row.zip_path)
            continue
        for named in (row.pending_dir, row.placing_dir):
            if named is not None:
                stale.append(Path(os.fsdecode(named)))
        session.delete(row)
    session.flush()
    return settled


def _rebuilt(
    service: "ScanService",
    job: "UploadJob",
    reader: BinaryIO,
    entries: Sequence[ZipEntry],
    repo: FoundRepo,
    folder: Path,
    limits: UploadLimits,
    deadline: float,
) -> Rebuilt | UploadRepoRefusal:
    private_folder(folder)
    try:
        extracted = extract_git_dir(
            reader, entries, repo, folder / "extracted", limits=limits, cancel=job.cancel
        )
        if not isinstance(extracted, Extracted):
            return extracted
        try:
            return rebuild(
                service.runner,
                extracted,
                folder / "rebuilt.git",
                timeout=max(1.0, deadline - time.monotonic()),
                cancel=job.cancel,
                ratio=limits.ratio,
            )
        finally:
            remove_tree(extracted.git_dir, ignore_errors=True)
    except (GitCancelled, ExtractCancelled):
        raise
    except (OSError, GitError):
        remove_tree(folder, ignore_errors=True)
        return UploadRepoRefusal.UNREADABLE


def _named(service: "ScanService", row_id: int, **values: bytes | None) -> bool:
    def name(session: "Session") -> bool:
        row = session.get(UploadRepo, row_id)
        if row is None:
            return False
        for column, value in values.items():
            setattr(row, column, value)
        return True

    return retry_busy(service.engine, name)


def _settle(
    service: "ScanService",
    row_id: int,
    made: Rebuilt,
    decision: Decision,
    user_id: int | None,
    done: _Pass,
    *,
    came_from: Path | None = None,
) -> None:
    data_dir = service.settings.data_dir
    with read_only(service.engine) as session:
        row_upload = session.scalar(select(UploadRepo.upload_id).where(UploadRepo.id == row_id))
        gone = row_upload is None or _discarded(session, row_upload)
    if gone:
        remove_tree(made.git_dir, ignore_errors=True)
        return
    if isinstance(decision, Ask):
        held = new_pending_dir(data_dir)
        private_folder(held.parent)
        if not _named(service, row_id, pending_dir=os.fsencode(held)):
            remove_tree(made.git_dir, ignore_errors=True)
            return
        try:
            os.replace(made.git_dir, held)
        except OSError:
            _named(service, row_id, pending_dir=None)
            raise

        def wait(session: "Session") -> None:
            row = session.get(UploadRepo, row_id)
            if row is not None:
                row.outcome = UploadRepoOutcome.WAITING
                row.candidates = list(decision.candidate_ids)
                row.dropped_objects = made.dropped_objects

        retry_busy(service.engine, wait)
        done.waiting += 1
        return
    target = new_version_dir(data_dir)
    private_folder(target.parent)
    if not _named(service, row_id, placing_dir=os.fsencode(target)):
        remove_tree(made.git_dir, ignore_errors=True)
        return
    try:
        os.replace(made.git_dir, target)
        placed = target.resolve(strict=True)
    except OSError:
        _named(service, row_id, placing_dir=None)
        raise

    def record(session: "Session") -> UploadRepoOutcome | None:
        row = session.get(UploadRepo, row_id)
        if row is None:
            return None
        owner = session.get(Upload, row.upload_id)
        if owner is None or owner.state is UploadState.DISCARDED:
            row.placing_dir = None
            return None
        row.dropped_objects = made.dropped_objects
        apply(
            session,
            decision,
            row,
            placed,
            commits=made.commits,
            user_id=user_id,
            now=utcnow(),
        )
        return row.outcome

    try:
        outcome = retry_busy(service.engine, record)
    except BaseException:
        _put_back(placed, came_from)
        _named(service, row_id, placing_dir=None)
        raise
    if outcome is None:
        remove_tree(placed, ignore_errors=True)
        return
    sweep_replaced(service.engine, data_dir)
    if outcome is UploadRepoOutcome.REPLACED:
        done.replaced += 1
    elif outcome is UploadRepoOutcome.NEW_VERSION:
        done.new_version += 1
    else:
        done.new += 1


def _put_back(placed: Path, came_from: Path | None) -> None:
    if came_from is not None and not os.path.lexists(came_from):
        with contextlib.suppress(OSError):
            os.replace(placed, came_from)
            return
    remove_tree(placed, ignore_errors=True)


def _current_version(session: "Session", repository_id: int) -> Path | None:
    found = session.scalars(
        select(RepositoryVersion.git_dir).where(
            RepositoryVersion.repository_id == repository_id,
            RepositoryVersion.current.is_(True),
            RepositoryVersion.removed_at.is_(None),
        )
    ).first()
    return None if found is None else Path(os.fsdecode(found))


def _apply_answered(
    service: "ScanService", job: "UploadJob", user_id: int | None, done: _Pass
) -> None:
    with read_only(service.engine) as session:
        answered = [
            (row.id, row.repository_id, row.pending_dir, row.dropped_objects)
            for row in session.scalars(
                select(UploadRepo).where(
                    UploadRepo.upload_id == job.id,
                    UploadRepo.outcome == UploadRepoOutcome.ANSWERED,
                )
            )
        ]
    for row_id, chosen, held, dropped in answered:
        if held is None:
            continue
        made = Rebuilt(Path(os.fsdecode(held)), None, dropped)
        decision: Decision = New()
        if chosen is not None:
            with read_only(service.engine) as session:
                current = _current_version(session, chosen)
            keep = current is not None and (
                dropped > 0
                or lacks_anything(
                    service.runner,
                    current,
                    made.git_dir,
                    scratch=staging_dir(service.settings.data_dir)
                    / str(job.id)
                    / f"scratch-{row_id}",
                    deadline=time.monotonic() + REPO_SECONDS,
                    cancel=job.cancel,
                )
            )
            decision = Update(chosen, keep_old=keep)
        _settle(service, row_id, made, decision, user_id, done, came_from=made.git_dir)


_APPLIED = (UploadRepoOutcome.NEW, UploadRepoOutcome.REPLACED, UploadRepoOutcome.NEW_VERSION)


def _to_scan(session: "Session", upload_id: int) -> list[int]:
    return list(
        session.scalars(
            select(UploadRepo.repository_id)
            .join(Repository, Repository.id == UploadRepo.repository_id)
            .where(
                UploadRepo.upload_id == upload_id,
                UploadRepo.outcome.in_(_APPLIED),
                Repository.deletion_state.is_(None),
            )
            .distinct()
            .order_by(UploadRepo.repository_id)
        )
    )


def _forget_pending(service: "ScanService", upload_id: int) -> None:
    def forget(session: "Session") -> list[Path]:
        held: list[Path] = []
        for row in session.scalars(
            select(UploadRepo).where(
                UploadRepo.upload_id == upload_id, UploadRepo.pending_dir.is_not(None)
            )
        ):
            if row.pending_dir is not None:
                held.append(Path(os.fsdecode(row.pending_dir)))
            row.pending_dir = None
            if row.outcome in (UploadRepoOutcome.WAITING, UploadRepoOutcome.ANSWERED):
                row.outcome = UploadRepoOutcome.DISCARDED
        return held

    for folder in retry_busy(service.engine, forget):
        _remove(folder)


def _after_discard(service: "ScanService", upload_id: int, user_id: int | None) -> None:
    service.upload_pieces.remove(upload_id)
    remove_tree(staging_dir(service.settings.data_dir) / str(upload_id), ignore_errors=True)
    _forget_pending(service, upload_id)
    with read_only(service.engine) as session:
        applied = _to_scan(session, upload_id)
    if not applied:
        return
    from gitmortem.scanning.service import ScanRefused

    with contextlib.suppress(ScanRefused), unit_of_work(service.engine) as session:
        service.plan_scan(session, applied, user_id)


def _end(
    service: "ScanService",
    job: "UploadJob",
    done: _Pass,
    user_id: int | None,
    *,
    failure: UploadFailure | None,
) -> None:
    data_dir = service.settings.data_dir
    if failure is not None:
        service.upload_pieces.remove(job.id)
        remove_tree(staging_dir(data_dir) / str(job.id), ignore_errors=True)
        _forget_pending(service, job.id)
    scan_id = None
    with read_only(service.engine) as session:
        discarded = _discarded(session, job.id)
        repositories = _to_scan(session, job.id) if failure is None else []
    if discarded:
        _after_discard(service, job.id, user_id)
        return
    if repositories:
        from gitmortem.scanning.service import Refusal, ScanRefused

        try:
            with unit_of_work(service.engine) as session:
                scan_id = service.plan_scan(session, repositories, user_id)
        except ScanRefused as refused:
            if refused.reason is Refusal.NOT_RUNNING:
                return
            if refused.reason is not Refusal.NO_TOOL_ENABLED:
                raise
    named: list[AuditValue] = list(repositories[: audit.NAME_SUBJECTS_UP_TO])
    with unit_of_work(service.engine) as session:
        upload = session.get(Upload, job.id)
        if upload is None or upload.state is UploadState.DISCARDED:
            return
        waiting = session.scalar(
            select(UploadRepo.id).where(
                UploadRepo.upload_id == job.id, UploadRepo.outcome == UploadRepoOutcome.WAITING
            )
        )
        now = utcnow()
        if failure is not None:
            upload.state, upload.failure = UploadState.FAILED, failure
        elif waiting is not None:
            upload.state = UploadState.WAITING
        else:
            upload.state = UploadState.DONE
        upload.updated_at = now
        if upload.state is not UploadState.WAITING:
            upload.finished_at = now
        if scan_id is not None:
            upload.scan_id = scan_id
        audit.record(
            session,
            AuditAction.UPLOAD_FINISHED,
            actor=None,
            detail={
                "upload_id": job.id,
                "new": done.new,
                "replaced": done.replaced,
                "new_version": done.new_version,
                "waiting": done.waiting,
                "refused": done.refused,
                "scan_id": scan_id,
                "repository_ids": named,
                **({"failure": failure.value} if failure is not None else {}),
            },
            at=now,
        )
