from pathlib import Path
from typing import cast

from apiflask import APIBlueprint, abort
from flask import current_app
from sqlalchemy import func, select

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.config import Settings, guarded_key_file
from gitmortem.db.models import DiscoveryRun, Role, ScanRoot, User, utcnow
from gitmortem.scanning.folders import list_folders
from gitmortem.scanning.roots import MESSAGES, RootRefused, root_is_usable, validate_root
from gitmortem.scanning.service import ScanRefused
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import get_db
from gitmortem.web.scans import refuse, running_scans
from gitmortem.web.schemas import (
    DiscoveryIdOut,
    RootFolderOut,
    RootFoldersIn,
    RootFoldersOut,
    ScanRootBasesOut,
    ScanRootIn,
    ScanRootListOut,
    ScanRootOut,
)
from gitmortem.web.security import client_ip, require_recent_password, require_role

SETTINGS = "gitmortem.settings"
NO_SUCH_ROOT = "No such scan root."

bp = APIBlueprint("scan_roots", __name__, url_prefix="/api/scan-roots")
ROOT_ID = "<id:root_id>"


def settings() -> Settings:
    return cast(Settings, current_app.extensions[SETTINGS])


@bp.get("", endpoint="list")
@require_role(Role.ANALYST)
@bp.output(ScanRootListOut)
def list_roots() -> ScanRootListOut:
    config = settings()
    newest = (
        select(DiscoveryRun.scan_root_id, func.max(DiscoveryRun.id).label("id"))
        .group_by(DiscoveryRun.scan_root_id)
        .subquery()
    )
    rows = get_db().execute(
        select(ScanRoot, User.username, newest.c.id)
        .outerjoin(User, ScanRoot.added_by_user_id == User.id)
        .outerjoin(newest, newest.c.scan_root_id == ScanRoot.id)
        .where(ScanRoot.removed_at.is_(None))
        .order_by(ScanRoot.path)
    )
    return ScanRootListOut(
        [
            _out(root, name, _usable(root.path, config), discovery_id)
            for root, name, discovery_id in rows
        ]
    )


@bp.get("/bases", endpoint="bases")
@require_role(Role.ADMIN)
@bp.output(ScanRootBasesOut)
def list_bases() -> ScanRootBasesOut:
    return ScanRootBasesOut(bases=[str(b) for b in settings().scan_root_bases])


@bp.post("/folders", endpoint="folders")
@require_role(Role.ADMIN)
@bp.input(RootFoldersIn, arg_name="asked")
@bp.output(RootFoldersOut)
@bp.doc(responses={422: "The folder is refused, as a root would be; the message says why"})
def browse_folders(asked: RootFoldersIn) -> RootFoldersOut:
    db = get_db()
    config = settings()
    active = [
        Path(p) for p in db.scalars(select(ScanRoot.path).where(ScanRoot.removed_at.is_(None)))
    ]
    db.rollback()
    try:
        listing = list_folders(
            asked.path,
            bases=config.scan_root_bases,
            data_dir=config.data_dir,
            key_file=guarded_key_file(config),
            active=active,
        )
    except RootRefused as refused:
        abort(422, MESSAGES[refused.reason])
    return RootFoldersOut(
        path=None if listing.path is None else str(listing.path),
        base=None if listing.base is None else str(listing.base),
        parent=None if listing.parent is None else str(listing.parent),
        folders=[
            RootFolderOut(
                name=folder.name,
                path=str(folder.path),
                readable=folder.readable,
                is_repository=folder.is_repository,
                repositories=folder.repositories,
                repositories_more=folder.repositories_more,
                root=folder.root,
                refusal=folder.refusal,
            )
            for folder in listing.folders
        ],
        truncated=listing.truncated,
        partial=listing.partial,
    )


@bp.post("", endpoint="add")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(ScanRootIn, arg_name="new")
@bp.output(ScanRootOut, status_code=201)
@bp.doc(responses={422: "The folder is refused; the message says why"})
def add(new: ScanRootIn) -> tuple[ScanRootOut, int]:
    db = get_db()
    config = settings()
    active = [
        Path(p) for p in db.scalars(select(ScanRoot.path).where(ScanRoot.removed_at.is_(None)))
    ]
    try:
        resolved = validate_root(
            new.path,
            bases=config.scan_root_bases,
            data_dir=config.data_dir,
            key_file=guarded_key_file(config),
            active=active,
        )
    except RootRefused as refused:
        db.rollback()
        abort(422, MESSAGES[refused.reason])
    actor = current_actor()
    path = str(resolved)
    root = db.scalars(select(ScanRoot).where(ScanRoot.path == path)).one_or_none()
    if root is None:
        root = ScanRoot(path=path, added_by_user_id=actor.id)
        db.add(root)
    else:
        root.removed_at = None
        root.added_by_user_id = actor.id
        root.added_at = utcnow()
    db.flush()
    audit.record(
        db, AuditAction.SCAN_ROOT_ADDED, actor=actor, ip=client_ip(), detail={"path": path}
    )
    newest = db.scalar(
        select(func.max(DiscoveryRun.id)).where(DiscoveryRun.scan_root_id == root.id)
    )
    return _out(root, actor.username, _usable(path, config), newest), 201


@bp.post(f"/{ROOT_ID}/remove", endpoint="remove")
@require_role(Role.ADMIN)
@require_recent_password
@bp.doc(responses={204: "Removed; its history is kept", 404: NO_SUCH_ROOT})
def remove(root_id: int) -> tuple[str, int]:
    db = get_db()
    root = db.get(ScanRoot, root_id)
    if root is None or root.removed_at is not None:
        db.rollback()
        abort(404, NO_SUCH_ROOT)
    root.removed_at = utcnow()
    audit.record(
        db,
        AuditAction.SCAN_ROOT_REMOVED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"path": root.path},
    )
    return "", 204


@bp.post(f"/{ROOT_ID}/discover", endpoint="discover")
@require_role(Role.ANALYST)
@bp.output(DiscoveryIdOut, status_code=202)
@bp.doc(
    responses={
        404: NO_SUCH_ROOT,
        409: "A discovery is already running for this root",
        422: "The root is gone or no longer inside a base the operator allowed",
        503: "Scanning is not running",
    }
)
def discover(root_id: int) -> tuple[DiscoveryIdOut, int]:
    service = running_scans()
    db = get_db()
    actor = current_actor()
    try:
        discovery_id = service.plan_discovery(db, root_id, actor.id)
    except ScanRefused as refused:
        refuse(refused)
    audit.record(
        db,
        AuditAction.DISCOVERY_STARTED,
        actor=actor,
        ip=client_ip(),
        detail={"discovery_id": discovery_id, "root_id": root_id},
    )
    service.notify()
    return DiscoveryIdOut(discovery_id=discovery_id), 202


def _usable(path: str, config: Settings) -> bool:
    return root_is_usable(
        path,
        bases=config.scan_root_bases,
        data_dir=config.data_dir,
        key_file=guarded_key_file(config),
    )


def _out(
    root: ScanRoot, added_by: str | None, usable: bool, last_discovery_id: int | None
) -> ScanRootOut:
    return ScanRootOut(
        id=root.id,
        path=root.path,
        usable=usable,
        added_by=added_by,
        added_at=root.added_at,
        last_discovery_id=last_discovery_id,
    )
