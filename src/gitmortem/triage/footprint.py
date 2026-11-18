from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Subquery, case, false, func, select, tuple_
from sqlalchemy.orm import Session

from gitmortem.db.models import Finding, FindingPlace, Repository, RepositoryKind, ToolName
from gitmortem.scanning.current import sighted_live, sighted_now
from gitmortem.triage.detail import _ORDER, FindingView, NoSuchFinding, _view, _views
from gitmortem.triage.query import clamped
from gitmortem.triage.subjects import Subject, SubjectKind, require

MAX_PLACES_PER_PAGE = 100
MAX_REPOSITORIES_PER_PAGE = 100
FINDINGS_PER_PLACE = 20

_KEY = (Finding.repository_id, Finding.commit, Finding.path, Finding.place, Finding.line)


@dataclass(frozen=True)
class Place:
    handle: int
    repository_id: int
    repo: str
    org: str | None
    repository_on_disk: bool
    commit: str
    display_path: str
    place: FindingPlace
    line: int
    tools: tuple[ToolName, ...]
    findings_total: int
    findings: list[FindingView]
    no_longer_reported: bool
    reported_live: bool
    first_authored_at: datetime | None


@dataclass(frozen=True)
class PlacePage:
    items: list[Place]
    page: int
    per_page: int
    total: int
    holding: int | None = None


@dataclass(frozen=True)
class FindingPage:
    items: list[FindingView]
    page: int
    per_page: int
    total: int


@dataclass(frozen=True)
class RepositorySummary:
    repository_id: int
    repo: str
    org: str | None
    repository_on_disk: bool
    places: int
    findings: int
    first_authored_at: datetime | None
    last_authored_at: datetime | None


@dataclass(frozen=True)
class RepositoryPage:
    items: list[RepositorySummary]
    page: int
    per_page: int
    total: int


def _bounded(page: int, per_page: int, most: int) -> tuple[int, int]:
    page, per_page = clamped(page, per_page)
    return page, min(per_page, most)


def _places(secret_id: int) -> Subquery:
    return (
        select(
            *_KEY,
            func.min(Finding.id).label("handle"),
            func.count().label("findings_total"),
            func.min(Finding.authored_at).label("first"),
        )
        .where(Finding.secret_id == secret_id)
        .group_by(*_KEY)
        .subquery("places")
    )


def _ordered(places: Subquery) -> tuple[Any, ...]:
    first = places.c.first
    return (first.is_(None), first, places.c.handle)


def _holding(session: Session, secret_id: int, finding_id: int, per_page: int) -> tuple[int, int]:
    places = _places(secret_id)
    key = session.execute(
        select(*_KEY).where(Finding.id == finding_id, Finding.secret_id == secret_id)
    ).first()
    if key is None:
        raise NoSuchFinding(finding_id)
    ranked = select(
        places.c.handle,
        *(getattr(places.c, column.key) for column in _KEY),
        func.row_number().over(order_by=_ordered(places)).label("n"),
    ).subquery()
    found = session.execute(
        select(ranked.c.n, ranked.c.handle).where(
            *(
                getattr(ranked.c, column.key) == value
                for column, value in zip(_KEY, key, strict=True)
            )
        )
    ).one()
    return (found.n - 1) // per_page + 1, found.handle


def places_page(
    session: Session, secret_id: int, *, page: int, per_page: int, finding: int | None
) -> PlacePage:
    require(session, Subject(SubjectKind.SECRET, secret_id))
    page, per_page = _bounded(page, per_page, MAX_PLACES_PER_PAGE)
    holding = None
    if finding is not None:
        page, holding = _holding(session, secret_id, finding, per_page)
    places = _places(secret_id)
    total = session.scalar(select(func.count()).select_from(places)) or 0
    shown = (
        select(places)
        .order_by(*_ordered(places))
        .limit(per_page)
        .offset((page - 1) * per_page)
        .subquery("shown")
    )
    rows = session.execute(
        select(shown, Repository.display_path, Repository.org, Repository.kind)
        .join(Repository, Repository.id == shown.c.repository_id)
        .order_by(*_ordered(shown))
    ).all()
    keys = [tuple(getattr(row, column.key) for column in _KEY) for row in rows]
    handle_of = dict(zip(keys, (row.handle for row in rows), strict=True))
    at = [Finding.secret_id == secret_id, tuple_(*_KEY).in_(keys)] if keys else [false()]
    marks: dict[int, tuple[bool, bool]] = {}
    tools: dict[int, set[ToolName]] = defaultdict(set)
    for found in session.execute(
        select(
            *_KEY,
            Finding.tool,
            func.max(case((sighted_now(Finding.id), 1), else_=0)).label("now"),
            func.max(case((sighted_live(Finding.id), 1), else_=0)).label("live"),
        )
        .where(*at)
        .group_by(*_KEY, Finding.tool)
    ):
        handle = handle_of[tuple(getattr(found, column.key) for column in _KEY)]
        seen, live = marks.get(handle, (False, False))
        marks[handle] = (seen or bool(found.now), live or bool(found.live))
        tools[handle].add(found.tool)
    ranked = (
        select(
            Finding.id,
            *_KEY,
            func.row_number().over(partition_by=_KEY, order_by=_ORDER).label("rn"),
        )
        .where(*at)
        .subquery()
    )
    owner = {
        found.id: handle_of[tuple(getattr(found, column.key) for column in _KEY)]
        for found in session.execute(select(ranked).where(ranked.c.rn <= FINDINGS_PER_PLACE))
    }
    embedded: dict[int, list[FindingView]] = defaultdict(list)
    if owner:
        for found in session.execute(_views(Finding.id.in_(list(owner)))):
            view = _view(found)
            embedded[owner[view.id]].append(view)
    items = []
    for row in rows:
        seen, live = marks.get(row.handle, (False, False))
        views = embedded[row.handle]
        items.append(
            Place(
                handle=row.handle,
                repository_id=row.repository_id,
                repo=row.display_path,
                org=row.org,
                repository_on_disk=row.kind is not RepositoryKind.NOT_ON_DISK,
                commit=row.commit,
                display_path=views[0].display_path,
                place=row.place,
                line=row.line,
                tools=tuple(sorted(tools[row.handle])),
                findings_total=row.findings_total,
                findings=views,
                no_longer_reported=not seen,
                reported_live=live,
                first_authored_at=row.first,
            )
        )
    return PlacePage(items=items, page=page, per_page=per_page, total=total, holding=holding)


def place_findings(
    session: Session,
    secret_id: int,
    handle: int,
    *,
    page: int,
    per_page: int,
    skip: int | None = None,
) -> FindingPage:
    require(session, Subject(SubjectKind.SECRET, secret_id))
    page, per_page = clamped(page, per_page)
    key = session.execute(
        select(*_KEY).where(Finding.id == handle, Finding.secret_id == secret_id)
    ).first()
    if key is None:
        raise NoSuchFinding(handle)
    here = [Finding.secret_id == secret_id] + [
        column == value for column, value in zip(_KEY, key, strict=True)
    ]
    total = session.scalar(select(func.count()).select_from(Finding).where(*here)) or 0
    offset = skip if skip is not None else (page - 1) * per_page
    found = session.execute(_views(*here).limit(per_page).offset(offset))
    return FindingPage(
        items=[_view(row) for row in found], page=page, per_page=per_page, total=total
    )


def repositories_page(
    session: Session, secret_id: int, *, page: int, per_page: int
) -> RepositoryPage:
    require(session, Subject(SubjectKind.SECRET, secret_id))
    page, per_page = _bounded(page, per_page, MAX_REPOSITORIES_PER_PAGE)
    places = _places(secret_id)
    per_repo = (
        select(
            places.c.repository_id,
            func.count().label("places"),
            func.sum(places.c.findings_total).label("findings"),
            func.min(places.c.first).label("first"),
        )
        .group_by(places.c.repository_id)
        .subquery("per_repo")
    )
    latest = (
        select(Finding.repository_id, func.max(Finding.authored_at).label("last"))
        .where(Finding.secret_id == secret_id)
        .group_by(Finding.repository_id)
        .subquery("latest")
    )
    total = session.scalar(select(func.count()).select_from(per_repo)) or 0
    found = session.execute(
        select(per_repo, latest.c.last, Repository.display_path, Repository.org, Repository.kind)
        .join(latest, latest.c.repository_id == per_repo.c.repository_id)
        .join(Repository, Repository.id == per_repo.c.repository_id)
        .order_by(per_repo.c.first.is_(None), per_repo.c.first, per_repo.c.repository_id)
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    return RepositoryPage(
        items=[
            RepositorySummary(
                repository_id=row.repository_id,
                repo=row.display_path,
                org=row.org,
                repository_on_disk=row.kind is not RepositoryKind.NOT_ON_DISK,
                places=row.places,
                findings=int(row.findings),
                first_authored_at=row.first,
                last_authored_at=row.last,
            )
            for row in found
        ],
        page=page,
        per_page=per_page,
        total=total,
    )


def views_of(page: PlacePage) -> Sequence[FindingView]:
    return [view for place in page.items for view in place.findings]
