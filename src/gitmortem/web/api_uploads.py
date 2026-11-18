import functools
from collections.abc import Callable
from typing import Any, NoReturn, cast

from apiflask import APIBlueprint, abort
from flask import request
from flask_login import current_user
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import Repository, RepositoryVersion, Role, Upload, UploadRepo, User
from gitmortem.uploads import records
from gitmortem.uploads.pieces import PIECE_BYTES
from gitmortem.uploads.records import UploadRefusal, UploadRefused
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import get_db
from gitmortem.web.scans import running_scans
from gitmortem.web.security import client_ip, note_refusal, now, require_role
from gitmortem.web.upload_schemas import (
    MAX_PIECE_BODY_BYTES,
    AnswerIn,
    CandidateOut,
    RepoUploadIn,
    RepoUploadPieceIn,
    UploadDetailOut,
    UploadListQueryIn,
    UploadOut,
    UploadPageOut,
    UploadRepoOut,
)

bp = APIBlueprint("uploads", __name__, url_prefix="/api/uploads")
UPLOAD_ID = "<id:upload_id>"
PIECE_TOO_LARGE = "A piece's body is at most 350,000 bytes."
REFUSAL_STATUS: dict[UploadRefusal, int] = {
    UploadRefusal.TOO_LARGE: 413,
    UploadRefusal.DISK_FULL: 503,
    UploadRefusal.NO_SUCH_UPLOAD: 404,
    UploadRefusal.NO_SUCH_REPO: 404,
    UploadRefusal.NOT_YOURS: 403,
    UploadRefusal.NOT_UPLOADING: 409,
    UploadRefusal.OUT_OF_ORDER: 409,
    UploadRefusal.INCOMPLETE: 409,
    UploadRefusal.NOT_WAITING: 409,
    UploadRefusal.ENDED: 409,
    UploadRefusal.TOO_MANY_OPEN: 429,
}


def _refused(refused: UploadRefused) -> NoReturn:
    get_db().rollback()
    if refused.reason is UploadRefusal.NOT_YOURS:
        note_refusal(refused.reason.value)
    abort(
        REFUSAL_STATUS.get(refused.reason, 422),
        str(refused),
        detail={"reason": refused.reason.value},
    )


def _bounded_body[V: Callable[..., Any]](limit: int) -> Callable[[V], V]:
    def decorate(view: V) -> V:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if (request.content_length or 0) > limit or len(request.get_data(cache=True)) > limit:
                abort(413, PIECE_TOO_LARGE)
            return view(*args, **kwargs)

        return cast(V, wrapper)

    return decorate


def _audit(action: AuditAction, detail: dict[str, Any]) -> None:
    audit.record(get_db(), action, actor=current_actor(), ip=client_ip(), detail=detail)


def _user_id() -> int | None:
    return cast(int | None, getattr(current_user, "id", None))


def _out(db: Session, upload: Upload) -> UploadOut:
    who = None if upload.created_by_user_id is None else db.get(User, upload.created_by_user_id)
    return UploadOut(
        id=upload.id,
        client_name=upload.client_name,
        org=upload.org_prefix,
        size_bytes=upload.size_bytes,
        last_modified_ms=upload.last_modified_ms,
        pieces=records.pieces_of(upload.size_bytes),
        piece_bytes=PIECE_BYTES,
        pieces_received=upload.pieces_received,
        state=upload.state,
        failure=upload.failure,
        created_by=None if who is None else who.username,
        mine=upload.created_by_user_id is not None and upload.created_by_user_id == _user_id(),
        created_at=upload.created_at,
        updated_at=upload.updated_at,
        finished_at=upload.finished_at,
        expires_at=records.expires_at(upload),
        scan_id=upload.scan_id,
    )


def _repos(db: Session, upload_id: int) -> list[UploadRepoOut]:
    rows = list(
        db.scalars(
            select(UploadRepo).where(UploadRepo.upload_id == upload_id).order_by(UploadRepo.id)
        )
    )
    wanted = {c for row in rows for c in row.candidates}
    shown = _candidates(db, wanted) if wanted else {}
    return [
        UploadRepoOut(
            id=row.id,
            zip_path=row.zip_path,
            org=row.org,
            name=row.name,
            outcome=row.outcome,
            refusal=row.refusal,
            repository_id=row.repository_id,
            candidates=[shown[c] for c in row.candidates if c in shown],
            dropped_objects=row.dropped_objects,
        )
        for row in rows
    ]


def _candidates(db: Session, wanted: set[int]) -> dict[int, CandidateOut]:
    current = {
        repository_id: (at, by)
        for repository_id, at, by in db.execute(
            select(
                RepositoryVersion.repository_id,
                RepositoryVersion.created_at,
                User.username,
            )
            .outerjoin(User, User.id == RepositoryVersion.created_by_user_id)
            .where(
                RepositoryVersion.repository_id.in_(wanted),
                RepositoryVersion.current.is_(True),
            )
        )
    }
    return {
        repo.id: CandidateOut(
            repository_id=repo.id,
            display_path=repo.display_path,
            org=repo.org,
            name=repo.name,
            commit_count=repo.commit_count,
            current_version_at=current.get(repo.id, (None, None))[0],
            current_version_by=current.get(repo.id, (None, None))[1],
        )
        for repo in db.scalars(select(Repository).where(Repository.id.in_(wanted)))
    }


def _detail(db: Session, upload: Upload) -> UploadDetailOut:
    return UploadDetailOut(**_out(db, upload).model_dump(), repos=_repos(db, upload.id))


@bp.post("", endpoint="create")
@require_role(Role.ANALYST)
@bp.input(RepoUploadIn, arg_name="new")
@bp.output(UploadOut, status_code=201)
def create(new: RepoUploadIn) -> tuple[UploadOut, int]:
    service = running_scans()
    db = get_db()
    try:
        made = records.create_upload(
            db,
            current_actor(),
            client_name=new.client_name,
            size_bytes=new.size_bytes,
            last_modified_ms=new.last_modified_ms,
            org_prefix=new.org,
            data_dir=service.settings.data_dir,
            now=now(),
        )
    except UploadRefused as refused:
        _refused(refused)
    _audit(AuditAction.UPLOAD_STARTED, {"upload_id": made.id, "size_bytes": made.size_bytes})
    return _out(db, made), 201


@bp.post(f"/{UPLOAD_ID}/pieces", endpoint="piece")
@require_role(Role.ANALYST)
@_bounded_body(MAX_PIECE_BODY_BYTES)
@bp.input(RepoUploadPieceIn, arg_name="piece")
@bp.output(UploadOut)
def add_piece(upload_id: int, piece: RepoUploadPieceIn) -> UploadOut:
    service = running_scans()
    try:
        data = piece.piece()
    except ValueError:
        abort(422, "A piece is base64.", detail={"reason": UploadRefusal.BAD_PIECE.value})
    db = get_db()
    try:
        upload = records.add_piece(
            db,
            service.upload_pieces,
            upload_id,
            _user_id(),
            piece.seq,
            data,
            data_dir=service.settings.data_dir,
            now=now(),
        )
    except UploadRefused as refused:
        _refused(refused)
    return _out(db, upload)


@bp.post(f"/{UPLOAD_ID}/finish", endpoint="finish")
@require_role(Role.ANALYST)
@bp.output(UploadOut, status_code=202)
def finish(upload_id: int) -> tuple[UploadOut, int]:
    service = running_scans()
    db = get_db()
    try:
        upload = records.finish_upload(db, upload_id, _user_id(), now=now())
    except UploadRefused as refused:
        _refused(refused)
    service.notify()
    return _out(db, upload), 202


@bp.get("", endpoint="list")
@require_role(Role.ANALYST)
@bp.input(UploadListQueryIn, location="query", arg_name="query")
@bp.output(UploadPageOut)
def list_uploads(query: UploadListQueryIn) -> UploadPageOut:
    db = get_db()
    total = db.scalar(select(func.count()).select_from(Upload)) or 0
    found = db.scalars(
        select(Upload)
        .order_by(Upload.id.desc())
        .offset((query.page - 1) * query.per_page)
        .limit(query.per_page)
    )
    return UploadPageOut(
        items=[_out(db, upload) for upload in found],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


@bp.get(f"/{UPLOAD_ID}", endpoint="get")
@require_role(Role.ANALYST)
@bp.output(UploadDetailOut)
def get_upload(upload_id: int) -> UploadDetailOut:
    db = get_db()
    upload = db.get(Upload, upload_id)
    if upload is None:
        abort(404, "No such upload.")
    return _detail(db, upload)


@bp.post(f"/{UPLOAD_ID}/repos/<id:repo_id>/answer", endpoint="answer")
@require_role(Role.ANALYST)
@bp.input(AnswerIn, arg_name="answer")
@bp.output(UploadDetailOut)
def answer(upload_id: int, repo_id: int, answer: AnswerIn) -> UploadDetailOut:
    service = running_scans()
    db = get_db()
    try:
        records.answer(db, upload_id, repo_id, answer.repository_id, current_actor(), now=now())
    except UploadRefused as refused:
        _refused(refused)
    _audit(
        AuditAction.UPLOAD_MATCH_ANSWERED,
        {"upload_id": upload_id, "upload_repo_id": repo_id, "repository_id": answer.repository_id},
    )
    service.notify()
    upload = db.get(Upload, upload_id)
    if upload is None:
        abort(404, "No such upload.")
    return _detail(db, upload)


@bp.post(f"/{UPLOAD_ID}/discard", endpoint="discard")
@require_role(Role.ANALYST)
@bp.output(UploadOut)
def discard(upload_id: int) -> UploadOut:
    service = running_scans()
    db = get_db()
    try:
        upload = records.discard(
            db,
            upload_id,
            current_actor(),
            service.upload_pieces,
            service.settings.data_dir,
            now=now(),
        )
    except UploadRefused as refused:
        _refused(refused)
    service.stop_upload(upload_id)
    _audit(AuditAction.UPLOAD_DISCARDED, {"upload_id": upload_id, "expired": False})
    return _out(db, upload)
