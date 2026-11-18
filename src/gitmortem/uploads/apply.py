import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from gitmortem.db.models import (
    Repository,
    RepositoryKind,
    RepositoryState,
    RepositoryVersion,
    ToolRun,
    ToolRunState,
    UploadRepo,
    UploadRepoOutcome,
)
from gitmortem.scanning.uow import read_only
from gitmortem.trees import remove_tree
from gitmortem.uploads.matching import Decision, New, Takeover, Update


@dataclass(frozen=True)
class Applied:
    repository_id: int
    replaced: tuple[Path, ...]


def _shown(org: str | None, name: str) -> str:
    return name if org is None else f"{org}/{name}"


def apply(
    session: Session,
    decision: Decision,
    upload_repo: UploadRepo,
    placed: Path,
    *,
    commits: int | None,
    user_id: int | None,
    now: datetime,
) -> Applied:
    replaced: list[Path] = []
    if isinstance(decision, Update | Takeover):
        named = session.get(Repository, decision.repository_id)
        if named is None or named.deletion_state is not None:
            decision = New()
    if isinstance(decision, New):
        repo = Repository(
            kind=RepositoryKind.UPLOADED,
            org=upload_repo.org,
            name=upload_repo.name,
            display_path=_shown(upload_repo.org, upload_repo.name),
            git_dir=os.fsencode(placed),
            state=RepositoryState.SCANNABLE,
            size_bytes=0,
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(repo)
        session.flush()
        outcome = UploadRepoOutcome.NEW
    elif isinstance(decision, Update | Takeover):
        found = session.get(Repository, decision.repository_id)
        if found is None:
            raise LookupError(f"no repository {decision.repository_id}")
        repo = found
        if isinstance(decision, Takeover):
            outcome = UploadRepoOutcome.NEW
        else:
            outcome = (
                UploadRepoOutcome.NEW_VERSION if decision.keep_old else UploadRepoOutcome.REPLACED
            )
            current = session.scalars(
                select(RepositoryVersion).where(
                    RepositoryVersion.repository_id == repo.id,
                    RepositoryVersion.current.is_(True),
                )
            ).all()
            for version in current:
                version.current = False
                if not decision.keep_old:
                    version.removed_at = now
                    replaced.append(Path(os.fsdecode(version.git_dir)))
            session.flush()
    else:
        raise ValueError("an Ask is answered before it is applied")
    version = RepositoryVersion(
        repository_id=repo.id,
        upload_repo_id=upload_repo.id,
        git_dir=os.fsencode(placed),
        current=True,
        created_by_user_id=user_id,
        created_at=now,
    )
    session.add(version)
    repo.git_dir = os.fsencode(placed)
    repo.kind = RepositoryKind.UPLOADED
    repo.state = RepositoryState.SCANNABLE
    repo.commit_count = commits
    repo.last_seen_at = now
    session.execute(
        update(UploadRepo)
        .where(UploadRepo.id == upload_repo.id)
        .values(outcome=outcome, repository_id=repo.id, pending_dir=None, placing_dir=None)
        .execution_options(synchronize_session="fetch")
    )
    session.flush()
    return Applied(repo.id, tuple(replaced))


def replaced_to_remove(session: Session) -> list[Path]:
    running = select(ToolRun.repository_id).where(ToolRun.state == ToolRunState.RUNNING)
    found = session.scalars(
        select(RepositoryVersion.git_dir)
        .join(Repository, RepositoryVersion.repository_id == Repository.id)
        .where(
            RepositoryVersion.removed_at.is_not(None),
            Repository.deletion_state.is_(None),
            RepositoryVersion.repository_id.not_in(running),
        )
    )
    return [path for path in (Path(os.fsdecode(raw)) for raw in found) if os.path.lexists(path)]


def sweep_replaced(engine: Engine, data_dir: Path) -> None:
    with read_only(engine) as session:
        replaced = replaced_to_remove(session)
    remove_replaced(data_dir, tuple(replaced))


def remove_replaced(data_dir: Path, replaced: tuple[Path, ...]) -> None:
    repos = (data_dir / "uploads" / "repos").resolve()
    for git_dir in replaced:
        real = git_dir.resolve()
        if real.is_relative_to(repos) and real != repos and not git_dir.is_symlink():
            remove_tree(real, ignore_errors=True)
