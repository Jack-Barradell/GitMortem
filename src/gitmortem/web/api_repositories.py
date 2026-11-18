import hmac
from collections.abc import Sequence

from apiflask import APIBlueprint, abort
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import (
    AuditValue,
    DeletionState,
    Repository,
    RepositoryKind,
    RepositoryVersion,
    Role,
    Upload,
    UploadRepo,
    User,
)
from gitmortem.deletion.jobs import DeletionBusy, start_deletion
from gitmortem.deletion.plan import DeletionPlan, plan_deletion, plan_digest
from gitmortem.scanning.repos import (
    NO_ORG_LABEL,
    UNSCANNED,
    ScanMark,
    list_repositories,
    org_choices,
    repository_page,
    scan_marks,
)
from gitmortem.web.actors import current_actor
from gitmortem.web.api_subjects import ID
from gitmortem.web.dbsession import get_db, read_phase
from gitmortem.web.scans import running_scans
from gitmortem.web.schemas import (
    DeleteRepositoriesIn,
    DeletionPreviewOut,
    DeletionStartedOut,
    LeftFolderOut,
    RepositoryIdsIn,
    RepositoryListIn,
    RepositoryListOut,
    RepositoryOrgOut,
    RepositoryOrgsIn,
    RepositoryOrgsOut,
    RepositoryOut,
    RepositoryPageOut,
    RepositoryQueryIn,
    UpdateOut,
    UpdatesPageOut,
    VersionOut,
)
from gitmortem.web.security import client_ip, now, require_recent_password, require_role
from gitmortem.web.upload_schemas import UploadListQueryIn

bp = APIBlueprint("repositories", __name__, url_prefix="/api/repositories")
NO_SUCH_REPOSITORY = "No such repository."


@bp.get("", endpoint="list")
@require_role(Role.ANALYST)
@bp.input(RepositoryQueryIn, location="query", arg_name="query")
@bp.output(RepositoryPageOut)
def list_repos(query: RepositoryQueryIn) -> RepositoryPageOut:
    db = get_db()
    rows, total = list_repositories(
        db,
        root_id=query.root,
        state=query.state,
        kind=query.kind,
        text=query.q,
        sort=query.sort,
        descending=query.order == "desc",
        page=query.page,
        per_page=query.per_page,
    )
    return RepositoryPageOut(
        items=_outs(db, rows), page=query.page, per_page=query.per_page, total=total
    )


@bp.post("/query", endpoint="query")
@require_role(Role.ANALYST)
@bp.input(RepositoryListIn, arg_name="body")
@bp.output(RepositoryListOut)
@bp.doc(responses={422: "An unknown field, sort or filter, or one out of its bounds"})
def query_repos(body: RepositoryListIn) -> RepositoryListOut:
    with read_phase() as db:
        rows, total, counts = repository_page(
            db,
            body.root,
            body.filters.filters(),
            sort=body.sort,
            descending=body.order == "desc",
            page=body.page,
            per_page=body.per_page,
        )
        items = _outs(db, rows)
    return RepositoryListOut(
        items=items,
        page=body.page,
        per_page=body.per_page,
        total=total,
        matching_scannable=counts.matching_scannable,
        root_scannable=counts.root_scannable,
        root_unscanned=counts.root_unscanned,
    )


@bp.post("/orgs", endpoint="orgs")
@require_role(Role.ANALYST)
@bp.input(RepositoryOrgsIn, arg_name="body")
@bp.output(RepositoryOrgsOut)
@bp.doc(responses={422: "An unknown field, or too much text"})
def list_orgs(body: RepositoryOrgsIn) -> RepositoryOrgsOut:
    with read_phase() as db:
        found = org_choices(db, body.root, body.text)
    return RepositoryOrgsOut(
        items=[
            RepositoryOrgOut(value=org, label=org or NO_ORG_LABEL, repositories=count)
            for org, count in found
        ]
    )


@bp.get(f"/{ID}", endpoint="get")
@require_role(Role.ANALYST)
@bp.output(RepositoryOut)
@bp.doc(responses={404: NO_SUCH_REPOSITORY})
def get_repo(id: int) -> RepositoryOut:
    db = get_db()
    repo = db.get(Repository, id)
    if repo is None:
        abort(404, NO_SUCH_REPOSITORY)
    return _outs(db, [repo])[0]


def _outs(db: Session, repos: Sequence[Repository]) -> list[RepositoryOut]:
    ids = [repo.id for repo in repos]
    if not ids:
        return []
    marks = scan_marks(db, ids)
    updates: dict[int, int] = {
        repository_id: count
        for repository_id, count in db.execute(
            select(UploadRepo.repository_id, func.count())
            .where(UploadRepo.repository_id.in_(ids))
            .group_by(UploadRepo.repository_id)
        )
        if repository_id is not None
    }
    uploaded = [repo.id for repo in repos if repo.kind is RepositoryKind.UPLOADED]
    versions: dict[int, list[VersionOut]] = {repository_id: [] for repository_id in uploaded}
    if uploaded:
        for version in db.scalars(
            select(RepositoryVersion)
            .where(
                RepositoryVersion.repository_id.in_(uploaded),
                RepositoryVersion.removed_at.is_(None),
            )
            .order_by(RepositoryVersion.current.desc(), RepositoryVersion.id.desc())
        ):
            versions[version.repository_id].append(
                VersionOut(id=version.id, current=version.current, created_at=version.created_at)
            )
    return [
        _out(repo, marks.get(repo.id, UNSCANNED), updates.get(repo.id, 0), versions.get(repo.id))
        for repo in repos
    ]


def _out(
    repo: Repository, mark: ScanMark, updates: int, versions: list[VersionOut] | None
) -> RepositoryOut:
    return RepositoryOut(
        id=repo.id,
        scan_root_id=repo.scan_root_id,
        display_path=repo.display_path,
        org=repo.org,
        name=repo.name,
        kind=repo.kind,
        state=repo.state,
        refusal=repo.refusal,
        commit_count=repo.commit_count,
        size_bytes=repo.size_bytes,
        last_seen_at=repo.last_seen_at,
        last_scanned_at=mark.last_scanned_at,
        scanning=mark.scanning,
        deletion_state=repo.deletion_state,
        deletion_failure=repo.deletion_failure,
        versions=versions,
        updates=updates,
    )


MAX_FOLDERS_SHOWN = 1_000
NO_SUCH_REPOSITORIES = "No such repository, or it was deleted."
DELETION_BUSY = "A repository chosen is already being deleted."
CONFIRM_MISMATCH = "The number typed is not the number of repositories the deletion takes now."
PLAN_CHANGED = "What this deletes has changed since the preview. Review it again."


def _planned(ids: list[int]) -> DeletionPlan:
    with read_phase() as db:
        found = list(db.scalars(select(Repository).where(Repository.id.in_(ids))))
        if len(found) != len(set(ids)) or any(
            r.deletion_state is DeletionState.DELETED for r in found
        ):
            abort(404, NO_SUCH_REPOSITORIES)
        if any(r.deletion_state is DeletionState.DELETING for r in found):
            abort(409, DELETION_BUSY)
        service = running_scans()
        plan = plan_deletion(db, service.runner, service.settings, ids)
    if plan.busy:
        abort(409, DELETION_BUSY)
    return plan


@bp.post("/deletion-preview", endpoint="deletion_preview")
@require_role(Role.ADMIN)
@bp.input(RepositoryIdsIn, arg_name="chosen")
@bp.output(DeletionPreviewOut)
def deletion_preview(chosen: RepositoryIdsIn) -> DeletionPreviewOut:
    plan = _planned(chosen.ids)
    folders = [removal.display for removal in plan.removals]
    return DeletionPreviewOut(
        repositories=plan.counts.repositories,
        findings=plan.counts.findings,
        secrets=plan.counts.secrets,
        with_triage=plan.counts.with_triage,
        delete_folders=folders[:MAX_FOLDERS_SHOWN],
        delete_folders_total=len(folders),
        left=[LeftFolderOut(folder=f.display, reason=f.reason) for f in plan.left],
        added_nested=sorted(set(plan.repositories) - set(chosen.ids)),
        digest=plan_digest(plan),
    )


@bp.post("/delete", endpoint="delete")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(DeleteRepositoriesIn, arg_name="chosen")
@bp.output(DeletionStartedOut, status_code=202)
def delete_repositories(chosen: DeleteRepositoriesIn) -> tuple[DeletionStartedOut, int]:
    plan = _planned(chosen.ids)
    if not hmac.compare_digest(chosen.digest, plan_digest(plan)):
        abort(409, PLAN_CHANGED, detail={"reason": "plan_changed"})
    if chosen.confirm != len(plan.repositories):
        abort(409, CONFIRM_MISMATCH, detail={"reason": "confirm_mismatch"})
    db = get_db()
    try:
        deletion = start_deletion(db, plan, current_actor(), now=now())
    except DeletionBusy:
        db.rollback()
        abort(409, DELETION_BUSY)
    audit.record(
        db,
        AuditAction.REPOSITORIES_DELETION_STARTED,
        actor=current_actor(),
        ip=client_ip(),
        detail={
            "deletion_id": deletion.id,
            "repositories": list[AuditValue](plan.repositories),
            "folders": list[AuditValue]([r.display for r in plan.removals][:MAX_FOLDERS_SHOWN]),
            "left": list[AuditValue]([f.display for f in plan.left]),
            "findings": plan.counts.findings,
            "secrets": plan.counts.secrets,
            "with_triage": plan.counts.with_triage,
        },
    )
    running_scans().notify()
    return DeletionStartedOut(deletion_id=deletion.id), 202


@bp.get(f"/{ID}/updates", endpoint="updates")
@require_role(Role.ANALYST)
@bp.input(UploadListQueryIn, location="query", arg_name="query")
@bp.output(UpdatesPageOut)
def repository_updates(id: int, query: UploadListQueryIn) -> UpdatesPageOut:
    db = get_db()
    if db.get(Repository, id) is None:
        abort(404, NO_SUCH_REPOSITORY)
    where = UploadRepo.repository_id == id
    total = db.scalar(select(func.count()).select_from(UploadRepo).where(where)) or 0
    rows = db.execute(
        select(UploadRepo, Upload, User.username)
        .join(Upload, Upload.id == UploadRepo.upload_id)
        .outerjoin(User, User.id == Upload.created_by_user_id)
        .where(where)
        .order_by(UploadRepo.id.desc())
        .offset((query.page - 1) * query.per_page)
        .limit(query.per_page)
    ).all()
    return UpdatesPageOut(
        items=[
            UpdateOut(
                upload_id=upload.id,
                client_name=upload.client_name,
                at=row.created_at,
                by=username,
                outcome=row.outcome,
            )
            for row, upload, username in rows
        ],
        page=query.page,
        per_page=query.per_page,
        total=total,
    )
