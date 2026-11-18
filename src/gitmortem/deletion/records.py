from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from gitmortem.crypto import RawStore
from gitmortem.db.models import (
    DeletionState,
    Finding,
    Import,
    ImportState,
    Note,
    Repository,
    RepositoryVersion,
    Secret,
    Sighting,
    StatusChange,
    ToolRun,
    ToolRunState,
    utcnow,
)
from gitmortem.scanning.store import recompute_imported_kinds

BATCH = 500


@dataclass(frozen=True)
class Removed:
    findings: int
    secrets: int
    with_triage: int


def _marked(session: Session, *, secrets: Collection[int], findings: Collection[int]) -> int:
    marked_secrets: set[int | None] = set()
    marked_findings: set[int | None] = set()
    for model in (StatusChange, Note):
        if secrets:
            marked_secrets |= set(
                session.scalars(
                    select(model.secret_id).distinct().where(model.secret_id.in_(secrets))
                )
            )
        if findings:
            marked_findings |= set(
                session.scalars(
                    select(model.finding_id).distinct().where(model.finding_id.in_(findings))
                )
            )
    return len(marked_secrets) + len(marked_findings)


def remove_batch(session: Session, repository_ids: Collection[int]) -> Removed | None:
    findings = list(
        session.execute(
            select(Finding.id, Finding.secret_id)
            .where(Finding.repository_id.in_(repository_ids))
            .limit(BATCH)
        )
    )
    if not findings:
        return None
    finding_ids = [finding_id for finding_id, _ in findings]
    secret_ids = {secret_id for _, secret_id in findings if secret_id is not None}
    standalone = [finding_id for finding_id, secret_id in findings if secret_id is None]
    with_triage = _marked(session, secrets=(), findings=standalone)
    for model in (StatusChange, Note):
        session.execute(delete(model).where(model.finding_id.in_(finding_ids)))
    session.execute(delete(Sighting).where(Sighting.finding_id.in_(finding_ids)))
    session.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
    still_held = set(
        session.scalars(select(Finding.secret_id).where(Finding.secret_id.in_(secret_ids)))
    )
    orphaned = secret_ids - still_held
    recompute_imported_kinds(session, secret_ids & still_held)
    if orphaned:
        with_triage += _marked(session, secrets=orphaned, findings=())
        for model in (StatusChange, Note):
            session.execute(delete(model).where(model.secret_id.in_(orphaned)))
        session.execute(delete(Secret).where(Secret.id.in_(orphaned)))
    session.flush()
    return Removed(len(finding_ids), len(orphaned), with_triage)


def finish_records(
    session: Session, raw_store: RawStore, repository_ids: Collection[int], *, now: datetime
) -> None:
    runs = session.execute(
        select(ToolRun.id, ToolRun.scan_id).where(ToolRun.repository_id.in_(repository_ids))
    ).all()
    for run_id, scan_id in runs:
        raw_store.remove_parts(scan_id, run_id)
    session.execute(
        update(ToolRun)
        .where(
            ToolRun.repository_id.in_(repository_ids),
            ToolRun.state.in_((ToolRunState.QUEUED, ToolRunState.RUNNING)),
        )
        .values(state=ToolRunState.CANCELLED, finished_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(ToolRun)
        .where(ToolRun.repository_id.in_(repository_ids))
        .values(raw_parts=[], findings_count=0)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(Import)
        .where(
            Import.repository_id.in_(repository_ids),
            Import.state.not_in((ImportState.REMOVED, ImportState.DISCARDED)),
        )
        .values(state=ImportState.REMOVED, removed_at=now)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(RepositoryVersion)
        .where(
            RepositoryVersion.repository_id.in_(repository_ids),
            RepositoryVersion.removed_at.is_(None),
        )
        .values(removed_at=now, current=False)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(Repository)
        .where(Repository.id.in_(repository_ids))
        .values(deletion_state=DeletionState.DELETED, deletion_failure=None, deleted_at=now)
        .execution_options(synchronize_session=False)
    )
    session.flush()
