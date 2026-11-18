import functools
from collections.abc import Callable
from typing import Any, NoReturn, cast

from apiflask import APIBlueprint, abort
from flask import request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import Import, Repository, RepositoryKind, Role, User
from gitmortem.scanning import imports
from gitmortem.scanning.imports import ImportRefusal, ImportRefused
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import get_db
from gitmortem.web.import_schemas import (
    ImportCheckOut,
    ImportOut,
    ImportPageOut,
    ImportQueryIn,
    PieceIn,
    RemovalIn,
    RemovalOut,
    ServerFileIn,
    UploadIn,
)
from gitmortem.web.scans import running_scans
from gitmortem.web.schemas import described
from gitmortem.web.security import client_ip, note_refusal, now, require_role

bp = APIBlueprint("imports", __name__, url_prefix="/api/imports")
IMPORT_ID = "<id:import_id>"
MAX_PIECE_BODY_BYTES = 350_000
NOT_RUNNING_DOC = "Scanning is not running"
PIECE_TOO_LARGE = f"A piece's body is at most {MAX_PIECE_BODY_BYTES:,} bytes."
REFUSAL_STATUS: dict[ImportRefusal, int] = {
    ImportRefusal.NOT_YOURS: 403,
    ImportRefusal.TOO_LARGE: 413,
    ImportRefusal.NO_SUCH_IMPORT: 404,
    ImportRefusal.NO_SUCH_REPOSITORY: 404,
    ImportRefusal.NOT_AN_UPLOAD: 409,
    ImportRefusal.NOT_UPLOADING: 409,
    ImportRefusal.OUT_OF_ORDER: 409,
    ImportRefusal.INCOMPLETE: 409,
    ImportRefusal.NOT_CHECKED: 409,
    ImportRefusal.CONFIRMED: 409,
    ImportRefusal.RECORDED: 409,
    ImportRefusal.NOT_RECORDED: 409,
    ImportRefusal.BUSY: 409,
    ImportRefusal.ENDED: 409,
    ImportRefusal.CHANGED: 409,
    ImportRefusal.REMOVAL_CHANGED: 409,
    ImportRefusal.REPOSITORY_BEING_DELETED: 409,
}
REFUSED_DOC: dict[str, Any] = {
    "description": (
        "Refused before anything was written: `detail.reason` names why, with fixed text; 404 "
        "for an unknown import or repository, 409 for a step the import's state does not take, "
        "413 past the ceiling"
    ),
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ImportRefusedOut"}}},
}
SERVER_FILE_CHANGED_DOC: dict[str, Any] = {
    **REFUSED_DOC,
    "description": (
        "The file, or a folder on its way, changed while it was checked (`detail.reason` "
        "`changed`): nothing was written"
    ),
}


def _refused(refused: ImportRefused) -> NoReturn:
    get_db().rollback()
    if refused.reason is ImportRefusal.NOT_YOURS:
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


def _names(db: Session, ids: set[int]) -> dict[int, str]:
    if not ids:
        return {}
    return {
        user_id: name
        for user_id, name in db.execute(select(User.id, User.username).where(User.id.in_(ids)))
    }


def _outs(db: Session, found: list[Import], *, viewer: User) -> list[ImportOut]:
    admin = viewer.role is Role.ADMIN
    names = _names(
        db,
        {
            user_id
            for each in found
            for user_id in (each.created_by_user_id, each.removed_by_user_id)
            if user_id is not None
        },
    )
    repositories = {
        repo_id: (path, kind)
        for repo_id, path, kind in db.execute(
            select(Repository.id, Repository.display_path, Repository.kind).where(
                Repository.id.in_({each.repository_id for each in found})
            )
        )
    }
    return [
        ImportOut(
            id=each.id,
            scan_id=each.scan_id,
            tool=each.tool,
            repository_id=each.repository_id,
            repository=repositories[each.repository_id][0],
            repository_on_disk=repositories[each.repository_id][1]
            is not RepositoryKind.NOT_ON_DISK,
            state=each.state,
            source=each.source,
            client_name=each.client_name,
            server_path=each.server_path if admin else None,
            size_bytes=each.size_bytes,
            pieces=each.pieces,
            pieces_received=each.pieces_received,
            check=None if each.check is None else ImportCheckOut.model_validate(each.check),
            failure=each.failure,
            failure_reason=each.failure_reason,
            created_by=names.get(each.created_by_user_id or 0),
            created_at=each.created_at,
            updated_at=each.updated_at,
            expires_at=imports.expires_at(each),
            recorded_at=each.recorded_at,
            removed_at=each.removed_at,
            removed_by=names.get(each.removed_by_user_id or 0),
            removable=imports.removable(db, each),
            mine=each.created_by_user_id == viewer.id,
        )
        for each in found
    ]


def _out(imported: Import) -> ImportOut:
    db = get_db()
    db.flush()
    (shown,) = _outs(db, [imported], viewer=current_actor())
    return shown


def _audit(action: AuditAction, detail: dict[str, Any]) -> None:
    audit.record(get_db(), action, actor=current_actor(), ip=client_ip(), detail=detail)


def _started(imported: Import) -> None:
    _audit(
        AuditAction.IMPORT_STARTED,
        {
            "import_id": imported.id,
            "scan_id": imported.scan_id,
            "tool": imported.tool.value,
            "source": imported.source.value,
        },
    )


@bp.post("", endpoint="create")
@require_role(Role.ANALYST)
@bp.input(UploadIn, arg_name="new")
@bp.output(ImportOut, status_code=201)
@bp.doc(
    responses=described(
        {404: REFUSED_DOC, 413: REFUSED_DOC, 422: REFUSED_DOC, 503: NOT_RUNNING_DOC}
    )
)
def create(new: UploadIn) -> tuple[ImportOut, int]:
    running_scans()
    try:
        made = imports.create_upload(
            get_db(),
            current_actor(),
            tool=new.tool,
            target=new.target.target(),
            client_name=new.client_name,
            size_bytes=new.size_bytes,
            now=now(),
        )
    except ImportRefused as refused:
        _refused(refused)
    _started(made)
    return _out(made), 201


@bp.post(f"/{IMPORT_ID}/pieces", endpoint="piece")
@require_role(Role.ANALYST)
@_bounded_body(MAX_PIECE_BODY_BYTES)
@bp.input(PieceIn, arg_name="piece")
@bp.output(ImportOut)
@bp.doc(
    responses=described(
        {404: REFUSED_DOC, 409: REFUSED_DOC, 413: PIECE_TOO_LARGE, 422: REFUSED_DOC}
    )
)
def add_piece(import_id: int, piece: PieceIn) -> ImportOut:
    service = running_scans()
    try:
        data = piece.piece()
    except ValueError:
        abort(422, "A piece is base64.", detail={"reason": ImportRefusal.BAD_PIECE.value})
    try:
        imported = imports.add_piece(
            get_db(),
            import_id,
            piece.seq,
            data,
            user=current_actor(),
            raw_store=service.raw_store,
            now=now(),
        )
    except ImportRefused as refused:
        _refused(refused)
    return _out(imported)


@bp.post(f"/{IMPORT_ID}/finish", endpoint="finish")
@require_role(Role.ANALYST)
@bp.output(ImportOut, status_code=202)
@bp.doc(responses=described({404: REFUSED_DOC, 409: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def finish(import_id: int) -> tuple[ImportOut, int]:
    service = running_scans()
    try:
        imported = imports.finish_upload(get_db(), import_id, user=current_actor(), now=now())
    except ImportRefused as refused:
        _refused(refused)
    service.notify()
    return _out(imported), 202


@bp.post("/server-file", endpoint="server_file")
@require_role(Role.ADMIN)
@bp.input(ServerFileIn, arg_name="named")
@bp.output(ImportOut, status_code=202)
@bp.doc(
    responses=described(
        {
            404: REFUSED_DOC,
            409: SERVER_FILE_CHANGED_DOC,
            413: REFUSED_DOC,
            422: REFUSED_DOC,
            503: NOT_RUNNING_DOC,
        }
    )
)
def server_file(named: ServerFileIn) -> tuple[ImportOut, int]:
    service = running_scans()
    try:
        made = imports.from_server_file(
            get_db(),
            current_actor(),
            tool=named.tool,
            target=named.target.target(),
            path=named.path,
            settings=service.settings,
            now=now(),
        )
    except ImportRefused as refused:
        _refused(refused)
    _started(made)
    service.notify()
    return _out(made), 202


@bp.get("", endpoint="list")
@require_role(Role.ANALYST)
@bp.input(ImportQueryIn, location="query", arg_name="query")
@bp.output(ImportPageOut)
@bp.doc(responses={503: NOT_RUNNING_DOC})
def list_imports(query: ImportQueryIn) -> ImportPageOut:
    running_scans()
    db = get_db()
    total = db.scalar(select(func.count()).select_from(Import)) or 0
    found = list(
        db.scalars(
            select(Import)
            .order_by(Import.id.desc())
            .limit(query.per_page)
            .offset((query.page - 1) * query.per_page)
        )
    )
    return ImportPageOut(
        items=_outs(db, found, viewer=current_actor()),
        page=query.page,
        per_page=query.per_page,
        total=total,
    )


@bp.get(f"/{IMPORT_ID}", endpoint="get")
@require_role(Role.ANALYST)
@bp.output(ImportOut)
@bp.doc(responses=described({404: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def get_import(import_id: int) -> ImportOut:
    running_scans()
    imported = get_db().get(Import, import_id)
    if imported is None:
        abort(404, "No such import.")
    return _out(imported)


@bp.post(f"/{IMPORT_ID}/confirm", endpoint="confirm")
@require_role(Role.ANALYST)
@bp.output(ImportOut, status_code=202)
@bp.doc(responses=described({404: REFUSED_DOC, 409: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def confirm(import_id: int) -> tuple[ImportOut, int]:
    service = running_scans()
    try:
        imported = imports.confirm(get_db(), import_id, user=current_actor())
    except ImportRefused as refused:
        _refused(refused)
    _audit(AuditAction.IMPORT_CONFIRMED, {"import_id": imported.id, "scan_id": imported.scan_id})
    service.notify()
    return _out(imported), 202


@bp.post(f"/{IMPORT_ID}/discard", endpoint="discard")
@require_role(Role.ANALYST)
@bp.output(ImportOut)
@bp.doc(responses=described({404: REFUSED_DOC, 409: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def discard(import_id: int) -> ImportOut:
    service = running_scans()
    try:
        imported = imports.discard(
            get_db(), import_id, user=current_actor(), raw_store=service.raw_store, now=now()
        )
    except ImportRefused as refused:
        _refused(refused)
    _audit(AuditAction.IMPORT_DISCARDED, {"import_id": imported.id})
    return _out(imported)


@bp.get(f"/{IMPORT_ID}/removal", endpoint="removal")
@require_role(Role.ANALYST)
@bp.output(RemovalOut)
@bp.doc(responses=described({404: REFUSED_DOC, 409: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def removal(import_id: int) -> RemovalOut:
    running_scans()
    try:
        counts = imports.removal_counts(get_db(), import_id)
    except ImportRefused as refused:
        _refused(refused)
    return _removal_out(counts)


def _removal_out(counts: imports.RemovalCounts) -> RemovalOut:
    return RemovalOut(
        findings=counts.findings,
        secrets=counts.secrets,
        with_triage=counts.with_triage,
        digest=counts.digest,
    )


@bp.post(f"/{IMPORT_ID}/remove", endpoint="remove")
@require_role(Role.ANALYST)
@bp.input(RemovalIn, arg_name="seen")
@bp.output(RemovalOut)
@bp.doc(responses=described({404: REFUSED_DOC, 409: REFUSED_DOC, 503: NOT_RUNNING_DOC}))
def remove(import_id: int, seen: RemovalIn) -> RemovalOut:
    service = running_scans()
    actor = current_actor()
    db = get_db()
    try:
        named = imports.removed_subjects(db, import_id)
        counts = imports.remove(
            db, import_id, digest=seen.digest, raw_store=service.raw_store, user=actor, now=now()
        )
    except ImportRefused as refused:
        _refused(refused)
    audit.record(
        db,
        AuditAction.IMPORT_REMOVED,
        actor=actor,
        ip=client_ip(),
        detail={
            "import_id": import_id,
            "findings": counts.findings,
            "secrets": counts.secrets,
            "with_triage": counts.with_triage,
        },
        subjects=named[: audit.NAME_SUBJECTS_UP_TO],
    )
    return _removal_out(counts)
