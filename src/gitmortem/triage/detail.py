from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, Row, Select, distinct, func, select
from sqlalchemy.orm import Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import (
    Finding,
    FindingPlace,
    Repository,
    RepositoryKind,
    Secret,
    SecretStatus,
    ToolName,
)
from gitmortem.scanning.current import sighted_live, sighted_now
from gitmortem.triage.query import clamped, latest_change_id
from gitmortem.triage.subjects import NoSuchSubject, Subject, SubjectKind, require


class NoSuchFinding(LookupError):
    def __init__(self, finding_id: int) -> None:
        super().__init__(f"no finding {finding_id}")
        self.finding_id = finding_id


@dataclass(frozen=True)
class FindingView:
    id: int
    repository_id: int
    repo: str
    org: str | None
    display_path: str
    line: int
    commit: str
    authored_at: datetime | None
    author_name: str
    author_email: str
    message_sealed: bytes | None = field(repr=False)
    message_cut: bool
    tool: ToolName
    rule: str
    first_seen_at: datetime
    secret_id: int | None
    status: SecretStatus | None
    place: FindingPlace = FindingPlace.LINE
    repository_on_disk: bool = True
    no_longer_reported: bool = False
    reported_live: bool = False


@dataclass(frozen=True)
class SecretView:
    id: int
    kind: str
    status: SecretStatus
    tools: tuple[ToolName, ...]
    first_seen: FindingView | None
    findings: int
    repos: int
    last_change_id: int


_ORDER = (Finding.authored_at.asc().nulls_last(), Finding.id.asc())


def _views(*where: ColumnElement[bool]) -> Select[*tuple[Any, ...]]:
    return (
        select(
            Finding.id,
            Finding.repository_id,
            Repository.display_path.label("repo"),
            Repository.org,
            Finding.display_path,
            Finding.line,
            Finding.commit,
            Finding.authored_at,
            Finding.author_name,
            Finding.author_email,
            Finding.message_sealed,
            Finding.message_cut,
            Finding.tool,
            Finding.rule,
            Finding.first_seen_at,
            Finding.secret_id,
            Finding.status,
            Finding.place,
            (Repository.kind != RepositoryKind.NOT_ON_DISK).label("repository_on_disk"),
            (~sighted_now(Finding.id)).label("no_longer_reported"),
            sighted_live(Finding.id).label("reported_live"),
        )
        .join(Repository, Repository.id == Finding.repository_id)
        .where(*where)
        .order_by(*_ORDER)
    )


def _view(found: Row[*tuple[Any, ...]]) -> FindingView:
    return FindingView(**found._mapping)


def message_of(sealer: Sealer, view: FindingView) -> str | None:
    if view.message_sealed is None:
        return None
    return sealer.open(view.message_sealed, Purpose.FINDING_MESSAGE).decode("utf-8", "replace")


def secret_detail(session: Session, secret_id: int) -> SecretView:
    secret = session.get(Secret, secret_id)
    if secret is None:
        raise NoSuchSubject(Subject(SubjectKind.SECRET, secret_id))
    held = Finding.secret_id == secret_id
    findings, repos = session.execute(
        select(func.count(), func.count(distinct(Finding.repository_id))).where(held)
    ).one()
    first = session.execute(_views(held).limit(1)).first()
    return SecretView(
        id=secret.id,
        kind=secret.kind,
        status=secret.status,
        tools=tuple(sorted(session.scalars(select(Finding.tool).where(held).distinct()))),
        first_seen=None if first is None else _view(first),
        findings=int(findings),
        repos=int(repos),
        last_change_id=latest_change_id(session),
    )


def secret_findings(
    session: Session, secret_id: int, *, page: int, per_page: int
) -> tuple[Sequence[FindingView], int]:
    require(session, Subject(SubjectKind.SECRET, secret_id))
    page, per_page = clamped(page, per_page)
    held = Finding.secret_id == secret_id
    total = session.scalar(select(func.count()).select_from(Finding).where(held)) or 0
    found = session.execute(_views(held).limit(per_page).offset((page - 1) * per_page))
    return [_view(row) for row in found], total


def page_holding(session: Session, secret_id: int, finding_id: int, *, per_page: int) -> int:
    require(session, Subject(SubjectKind.SECRET, secret_id))
    _, per_page = clamped(1, per_page)
    ranked = (
        select(Finding.id, func.row_number().over(order_by=_ORDER).label("place"))
        .where(Finding.secret_id == secret_id)
        .subquery()
    )
    place: int | None = session.scalar(select(ranked.c.place).where(ranked.c.id == finding_id))
    if place is None:
        raise NoSuchFinding(finding_id)
    return (place - 1) // per_page + 1


def finding_view(session: Session, finding_id: int) -> FindingView:
    found = session.execute(_views(Finding.id == finding_id)).first()
    if found is None:
        raise NoSuchFinding(finding_id)
    return _view(found)
