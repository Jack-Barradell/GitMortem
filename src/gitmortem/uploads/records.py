import os
import shutil
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import (
    Role,
    Upload,
    UploadRepo,
    UploadRepoOutcome,
    UploadState,
    User,
)
from gitmortem.scanning.imports import CLIENT_NAME_CHARS, NAME_CHARS, plain_name
from gitmortem.scanning.settings import get_upload_limits
from gitmortem.trees import remove_tree
from gitmortem.uploads.pieces import PIECE_BYTES, UploadPieces
from gitmortem.uploads.place import DISK_RESERVE_BYTES, staging_dir

UPLOAD_EXPIRES = timedelta(hours=24)


DISCARDABLE = frozenset(
    {UploadState.UPLOADING, UploadState.QUEUED, UploadState.PROCESSING, UploadState.WAITING}
)


class UploadRefusal(StrEnum):
    TOO_LARGE = "too_large"
    EMPTY = "empty"
    BAD_NAME = "bad_name"
    DISK_FULL = "disk_full"
    NO_SUCH_UPLOAD = "no_such_upload"
    NO_SUCH_REPO = "no_such_repo"
    NOT_YOURS = "not_yours"
    NOT_UPLOADING = "not_uploading"
    OUT_OF_ORDER = "out_of_order"
    BAD_PIECE = "bad_piece"
    INCOMPLETE = "incomplete"
    NOT_WAITING = "not_waiting"
    NOT_A_CANDIDATE = "not_a_candidate"
    ENDED = "ended"
    TOO_MANY_OPEN = "too_many_open"


MAX_OPEN_PER_USER = 5
MAX_OPEN = 20

REFUSALS_TEXT: dict[UploadRefusal, str] = {
    UploadRefusal.TOO_LARGE: "The zip is larger than this instance's upload limit.",
    UploadRefusal.EMPTY: "An upload holds at least one byte.",
    UploadRefusal.BAD_NAME: "A file name or org is 1 to its limit of characters, none a control.",
    UploadRefusal.DISK_FULL: "There is not enough free disk to hold the upload.",
    UploadRefusal.NO_SUCH_UPLOAD: "No such upload.",
    UploadRefusal.NO_SUCH_REPO: "No such repository in this upload.",
    UploadRefusal.NOT_YOURS: "Only the user who started an upload, or an admin, may do that.",
    UploadRefusal.NOT_UPLOADING: "The upload is not taking pieces.",
    UploadRefusal.OUT_OF_ORDER: "Pieces are sent in order, each once.",
    UploadRefusal.BAD_PIECE: "A piece is 256 KiB of the file, but the last, which is the rest.",
    UploadRefusal.INCOMPLETE: "Not every piece of the upload has arrived.",
    UploadRefusal.NOT_WAITING: "That repository is not waiting for an answer.",
    UploadRefusal.NOT_A_CANDIDATE: "Answer with one of the repositories offered, or a new one.",
    UploadRefusal.ENDED: "The upload is being processed or has ended.",
    UploadRefusal.TOO_MANY_OPEN: (
        "Too many uploads are still taking pieces: finish or discard one before starting another."
    ),
}


class UploadRefused(Exception):
    def __init__(self, reason: UploadRefusal) -> None:
        super().__init__(REFUSALS_TEXT[reason])
        self.reason = reason


def pieces_of(size: int) -> int:
    return -(-size // PIECE_BYTES)


def expires_at(upload: Upload) -> datetime | None:
    if upload.state in (UploadState.UPLOADING, UploadState.WAITING):
        return upload.updated_at + UPLOAD_EXPIRES
    return None


def _free(data_dir: Path) -> int:
    where = data_dir
    while not where.exists() and where != where.parent:
        where = where.parent
    return shutil.disk_usage(where).free


def create_upload(
    session: Session,
    user: User | None,
    *,
    client_name: str,
    size_bytes: int,
    last_modified_ms: int,
    org_prefix: str | None,
    data_dir: Path,
    now: datetime,
) -> Upload:
    if size_bytes < 1:
        raise UploadRefused(UploadRefusal.EMPTY)
    if size_bytes > get_upload_limits(session).upload_bytes:
        raise UploadRefused(UploadRefusal.TOO_LARGE)
    try:
        plain_name(client_name, CLIENT_NAME_CHARS)
        if org_prefix is not None:
            plain_name(org_prefix, NAME_CHARS)
    except ValueError:
        raise UploadRefused(UploadRefusal.BAD_NAME) from None
    open_ones = [
        (owner, size, received)
        for owner, size, received in session.execute(
            select(Upload.created_by_user_id, Upload.size_bytes, Upload.pieces_received).where(
                Upload.state == UploadState.UPLOADING
            )
        )
    ]
    mine = sum(1 for owner, _, _ in open_ones if user is not None and owner == user.id)
    if len(open_ones) >= MAX_OPEN or mine >= MAX_OPEN_PER_USER:
        raise UploadRefused(UploadRefusal.TOO_MANY_OPEN)
    coming = sum(max(0, size - received * PIECE_BYTES) for _, size, received in open_ones)
    if _free(data_dir) < size_bytes + coming + DISK_RESERVE_BYTES:
        raise UploadRefused(UploadRefusal.DISK_FULL)
    made = Upload(
        created_by_user_id=None if user is None else user.id,
        client_name=client_name,
        org_prefix=org_prefix,
        size_bytes=size_bytes,
        last_modified_ms=last_modified_ms,
        pieces_received=0,
        state=UploadState.UPLOADING,
        created_at=now,
        updated_at=now,
    )
    session.add(made)
    session.flush()
    return made


def _upload(session: Session, upload_id: int) -> Upload:
    found = session.get(Upload, upload_id)
    if found is None:
        raise UploadRefused(UploadRefusal.NO_SUCH_UPLOAD)
    return found


def add_piece(
    session: Session,
    pieces: UploadPieces,
    upload_id: int,
    user_id: int | None,
    seq: int,
    data: bytes,
    *,
    data_dir: Path,
    now: datetime,
) -> Upload:
    upload = _upload(session, upload_id)
    if upload.created_by_user_id is None or upload.created_by_user_id != user_id:
        raise UploadRefused(UploadRefusal.NOT_YOURS)
    if upload.state is not UploadState.UPLOADING:
        raise UploadRefused(UploadRefusal.NOT_UPLOADING)
    total = pieces_of(upload.size_bytes)
    if seq != upload.pieces_received + 1 or seq > total:
        raise UploadRefused(UploadRefusal.OUT_OF_ORDER)
    wanted = PIECE_BYTES if seq < total else upload.size_bytes - (total - 1) * PIECE_BYTES
    if len(data) != wanted:
        raise UploadRefused(UploadRefusal.BAD_PIECE)
    if _free(data_dir) < len(data) + DISK_RESERVE_BYTES:
        raise UploadRefused(UploadRefusal.DISK_FULL)
    pieces.write(upload.id, seq, data)
    upload.pieces_received = seq
    upload.updated_at = now
    session.flush()
    return upload


def finish_upload(
    session: Session, upload_id: int, user_id: int | None, *, now: datetime
) -> Upload:
    upload = _upload(session, upload_id)
    if upload.created_by_user_id is None or upload.created_by_user_id != user_id:
        raise UploadRefused(UploadRefusal.NOT_YOURS)
    if upload.state is not UploadState.UPLOADING:
        raise UploadRefused(UploadRefusal.NOT_UPLOADING)
    if upload.pieces_received != pieces_of(upload.size_bytes):
        raise UploadRefused(UploadRefusal.INCOMPLETE)
    upload.state = UploadState.QUEUED
    upload.updated_at = now
    session.flush()
    return upload


def answer(
    session: Session,
    upload_id: int,
    upload_repo_id: int,
    repository_id: int | None,
    user: User | None,
    *,
    now: datetime,
) -> UploadRepo:
    upload = _upload(session, upload_id)
    row = session.get(UploadRepo, upload_repo_id)
    if row is None or row.upload_id != upload.id:
        raise UploadRefused(UploadRefusal.NO_SUCH_REPO)
    is_admin = user is not None and user.role is Role.ADMIN
    if not is_admin and (user is None or upload.created_by_user_id != user.id):
        raise UploadRefused(UploadRefusal.NOT_YOURS)
    if upload.state is not UploadState.WAITING or row.outcome is not UploadRepoOutcome.WAITING:
        raise UploadRefused(UploadRefusal.NOT_WAITING)
    if repository_id is not None and repository_id not in row.candidates:
        raise UploadRefused(UploadRefusal.NOT_A_CANDIDATE)
    row.outcome = UploadRepoOutcome.ANSWERED
    row.repository_id = repository_id
    row.answered_by_user_id = None if user is None else user.id
    row.answered_at = now
    upload.state = UploadState.QUEUED
    upload.updated_at = now
    session.flush()
    return row


def _remove_files(upload: Upload, session: Session, pieces: UploadPieces, data_dir: Path) -> None:
    pieces.remove(upload.id)
    remove_tree(staging_dir(data_dir) / str(upload.id), ignore_errors=True)
    pending_root = (data_dir / "uploads" / "pending").resolve()
    for row in session.scalars(select(UploadRepo).where(UploadRepo.upload_id == upload.id)):
        if row.pending_dir is not None:
            held = Path(os.fsdecode(row.pending_dir))
            if held.resolve().is_relative_to(pending_root) and not held.is_symlink():
                remove_tree(held, ignore_errors=True)
            row.pending_dir = None
        if row.outcome in (UploadRepoOutcome.WAITING, UploadRepoOutcome.PENDING):
            row.outcome = UploadRepoOutcome.DISCARDED


def discard(
    session: Session,
    upload_id: int,
    user: User | None,
    pieces: UploadPieces,
    data_dir: Path,
    *,
    now: datetime,
) -> Upload:
    upload = _upload(session, upload_id)
    is_admin = user is not None and user.role is Role.ADMIN
    if not is_admin and (user is None or upload.created_by_user_id != user.id):
        raise UploadRefused(UploadRefusal.NOT_YOURS)
    if upload.state not in DISCARDABLE:
        raise UploadRefused(UploadRefusal.ENDED)
    running = upload.state is UploadState.PROCESSING
    upload.state = UploadState.DISCARDED
    upload.finished_at = now
    if running:
        for row in session.scalars(select(UploadRepo).where(UploadRepo.upload_id == upload.id)):
            if row.outcome in (UploadRepoOutcome.WAITING, UploadRepoOutcome.PENDING):
                row.outcome = UploadRepoOutcome.DISCARDED
    else:
        _remove_files(upload, session, pieces, data_dir)
    session.flush()
    return upload


def expire_uploads(
    session: Session, pieces: UploadPieces, data_dir: Path, now: datetime
) -> list[int]:
    stale = list(
        session.scalars(
            select(Upload).where(
                Upload.state.in_((UploadState.UPLOADING, UploadState.WAITING)),
                Upload.updated_at < now - UPLOAD_EXPIRES,
            )
        )
    )
    for upload in stale:
        upload.state = UploadState.DISCARDED
        upload.finished_at = now
        _remove_files(upload, session, pieces, data_dir)
        audit.record(
            session,
            AuditAction.UPLOAD_DISCARDED,
            actor=None,
            detail={"upload_id": upload.id, "expired": True},
            at=now,
        )
    session.flush()
    return [upload.id for upload in stale]
