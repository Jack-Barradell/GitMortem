from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from sqlalchemy import (
    CTE,
    BindParameter,
    ColumnElement,
    UnaryExpression,
    and_,
    bindparam,
    case,
    distinct,
    func,
    literal,
    or_,
    select,
)
from sqlalchemy.orm import Session, aliased

from gitmortem.db import like
from gitmortem.db.models import (
    Deletion,
    Finding,
    Import,
    ImportState,
    Repository,
    RepositoryKind,
    Scan,
    ScanState,
    Secret,
    SecretStatus,
    Sighting,
    StatusChange,
    ToolName,
    ToolRun,
)
from gitmortem.scanning.current import current_sighting, live_sighting
from gitmortem.triage.subjects import Subject, SubjectKind

MAX_PER_PAGE = 200
LIST_MAX_PER_PAGE = 500
MAX_PAGE = 1_000_000_000
MAX_TEXT = 256
MAX_PATHS = 50
MAX_PATH_CHARS = 4096
MAX_PATH_CHOICES = 50
MAX_CHOICES = 50
MAX_FACET_SCANS = 200
ENDED_SCAN = frozenset({ScanState.FINISHED, ScanState.CANCELLED, ScanState.INTERRUPTED})

Order = Literal["asc", "desc"]


class View(StrEnum):
    UNIQUE = "unique"
    ALL = "all"


class ListSort(StrEnum):
    DATE = "date"
    REPO = "repo"
    ORG = "org"
    PATH = "path"
    TYPE = "type"
    TOOL = "tool"
    STATUS = "status"
    FINDINGS = "findings"
    REPOS = "repos"
    VALUE = "value"


class ScanScope(StrEnum):
    SEEN = "seen"
    NEW = "new"


class ReportedScope(StrEnum):
    ALL = "all"
    CURRENT = "current"
    NO_LONGER = "no_longer"


@dataclass(frozen=True)
class Filters:
    orgs: tuple[str, ...] = ()
    repository_ids: tuple[int, ...] = ()
    paths: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    kinds_negated: bool = False
    tools: tuple[ToolName, ...] = ()
    statuses: tuple[SecretStatus, ...] = ()
    statuses_negated: bool = False
    authored_from: datetime | None = None
    authored_to: datetime | None = None
    scan_id: int | None = None
    scan_scope: ScanScope = ScanScope.SEEN
    reported: ReportedScope = ReportedScope.ALL
    reported_live: bool | None = None
    reused: bool | None = None
    no_org: bool = False
    text: str | None = field(default=None, repr=False)
    message_ids: frozenset[int] | None = field(default=None, repr=False, compare=False)
    canary: bool = False
    canary_ids: frozenset[int] | None = field(default=None, repr=False, compare=False)

    @property
    def searches_sealed(self) -> bool:
        return bool(self.text) or self.canary

    def __post_init__(self) -> None:
        if self.text is not None and len(self.text) > MAX_TEXT:
            raise ValueError(f"the text filter is longer than {MAX_TEXT} characters")
        if len(self.paths) > MAX_PATHS:
            raise ValueError(f"the file filter names more than {MAX_PATHS} paths")


@dataclass(frozen=True)
class ReportedMark:
    removed_imports: int
    deleted_findings: int
    superseded_runs: int
    sightings: int
    live_sightings: int


@dataclass(frozen=True)
class Bound:
    max_secret_id: int
    max_finding_id: int
    scan_ended: bool | None = None
    reported_mark: ReportedMark | None = None


@dataclass(frozen=True)
class Row:
    subject: Subject
    anchor_finding_id: int
    repository_id: int
    org: str | None
    repo_name: str
    display_path: str
    commit: str
    authored_at: datetime | None
    kind: str
    tools: tuple[ToolName, ...]
    status: SecretStatus
    findings: int
    repos: int
    no_longer_reported: bool
    reported_live: bool = False
    repository_on_disk: bool = True


@dataclass(frozen=True)
class ListPage:
    rows: list[Row]
    total_findings: int | None
    total_unique: int | None
    bound: Bound
    last_change_id: int
    by_status: list["Group"] | None = None
    by_tool: list["Group"] | None = None


@dataclass(frozen=True)
class Group:
    key: Any
    label: str | None
    findings: int
    unique: int


@dataclass(frozen=True)
class PathChoice:
    path: str
    findings: int
    unique: int


class ChoiceDimension(StrEnum):
    REPOSITORY = "repository"
    ORG = "org"
    KIND = "kind"


NO_ORG = ""
NO_ORG_LABEL = "No org"


@dataclass(frozen=True)
class Choice:
    value: int | str
    label: str
    findings: int
    unique: int


@dataclass(frozen=True)
class Facets:
    tools: list[ToolName]
    scans: list[tuple[int, datetime, ScanState]]


_SORT_COLUMN: Mapping[ListSort, str] = {
    ListSort.DATE: "authored_at",
    ListSort.REPO: "repo_name",
    ListSort.ORG: "org",
    ListSort.PATH: "display_path",
    ListSort.TYPE: "kind",
    ListSort.TOOL: "first_tool",
    ListSort.STATUS: "status_rank",
    ListSort.FINDINGS: "findings",
    ListSort.REPOS: "repos",
}
_STATUS_RANK = {status.value: rank for rank, status in enumerate(SecretStatus)}
_TOOL_FLAGS = {tool: f"has_tool_{n}" for n, tool in enumerate(ToolName)}


class MessagesNotSearched(RuntimeError):
    def __init__(self) -> None:
        super().__init__("a text filter reached the query before its messages were searched")


def _ids(name: str, ids: Collection[int]) -> BindParameter[int]:
    return bindparam(name, sorted(ids), expanding=True, literal_execute=True)


def _only(subjects: Collection[Subject]) -> ColumnElement[bool]:
    secrets = {s.id for s in subjects if s.kind is SubjectKind.SECRET}
    findings = {s.id for s in subjects if s.kind is SubjectKind.FINDING}
    return or_(
        Finding.secret_id.in_(_ids("only_secrets", secrets)),
        and_(Finding.secret_id.is_(None), Finding.id.in_(_ids("only_findings", findings))),
    )


def _in_scan(scan_id: int, scope: ScanScope) -> ColumnElement[bool]:
    runs = select(ToolRun.id).where(ToolRun.scan_id == scan_id)
    seen = Finding.id.in_(select(Sighting.finding_id).where(Sighting.tool_run_id.in_(runs)))
    if scope is ScanScope.SEEN:
        return seen
    first = (
        select(func.min(Sighting.tool_run_id))
        .where(Sighting.finding_id == Finding.id)
        .scalar_subquery()
    )
    return and_(seen, first.in_(runs))


def _subject_reported() -> ColumnElement[bool]:
    seen = aliased(Finding)
    current_secrets = (
        select(seen.secret_id)
        .join(Sighting, Sighting.finding_id == seen.id)
        .join(ToolRun, ToolRun.id == Sighting.tool_run_id)
        .where(ToolRun.superseded_at.is_(None), seen.secret_id.is_not(None))
    )
    return or_(
        and_(Finding.secret_id.is_(None), Finding.id.in_(current_sighting())),
        and_(Finding.secret_id.is_not(None), Finding.secret_id.in_(current_secrets)),
    )


def _subject_live() -> ColumnElement[bool]:
    seen = aliased(Finding)
    live_secrets = (
        select(seen.secret_id)
        .join(Sighting, Sighting.finding_id == seen.id)
        .join(ToolRun, ToolRun.id == Sighting.tool_run_id)
        .where(
            ToolRun.superseded_at.is_(None),
            Sighting.reported_live.is_(True),
            seen.secret_id.is_not(None),
        )
    )
    return or_(
        and_(Finding.secret_id.is_(None), Finding.id.in_(live_sighting())),
        and_(Finding.secret_id.is_not(None), Finding.secret_id.in_(live_secrets)),
    )


def _live(live: bool, view: View) -> ColumnElement[bool]:
    if live:
        return Finding.id.in_(live_sighting())
    if view is View.ALL:
        return ~Finding.id.in_(live_sighting())
    return ~_subject_live()


def _reported(scope: ReportedScope, view: View) -> ColumnElement[bool]:
    if scope is ReportedScope.CURRENT:
        return Finding.id.in_(current_sighting())
    if view is View.ALL:
        return ~Finding.id.in_(current_sighting())
    return ~_subject_reported()


def _conditions(
    filters: Filters,
    view: View,
    kind: ColumnElement[str],
    status: ColumnElement[SecretStatus],
    bound: Bound | None,
    only: Collection[Subject] | None,
) -> list[ColumnElement[bool]]:
    where: list[ColumnElement[bool]] = []
    if filters.orgs and filters.no_org:
        where.append(or_(Repository.org.in_(filters.orgs), Repository.org.is_(None)))
    elif filters.orgs:
        where.append(Repository.org.in_(filters.orgs))
    elif filters.no_org:
        where.append(Repository.org.is_(None))
    if filters.repository_ids:
        where.append(Finding.repository_id.in_(filters.repository_ids))
    if filters.paths:
        where.append(Finding.display_path.in_(filters.paths))
    if filters.kinds:
        named = kind.in_(filters.kinds)
        where.append(~named if filters.kinds_negated else named)
    if filters.tools:
        where.append(Finding.tool.in_(filters.tools))
    if filters.statuses:
        chosen = status.in_(filters.statuses)
        where.append(~chosen if filters.statuses_negated else chosen)
    if filters.authored_from is not None:
        where.append(Finding.authored_at >= filters.authored_from)
    if filters.authored_to is not None:
        where.append(Finding.authored_at < filters.authored_to)
    if filters.scan_id is not None:
        where.append(_in_scan(filters.scan_id, filters.scan_scope))
    if filters.reported is not ReportedScope.ALL:
        where.append(_reported(filters.reported, view))
    if filters.reported_live is not None:
        where.append(_live(filters.reported_live, view))
    if filters.reused is not None:
        where.append(_reused(filters.reused, bound))
    if filters.text:
        if filters.message_ids is None:
            raise MessagesNotSearched
        pattern = like.anywhere(filters.text)
        searched = (
            Finding.display_path,
            kind,
            Finding.author_name,
            Finding.author_email,
            Repository.display_path,
        )
        where.append(
            or_(
                *(column.ilike(pattern, escape=like.ESCAPE) for column in searched),
                Finding.id.in_(_ids("text_messages", filters.message_ids)),
            )
        )
    if filters.canary:
        if filters.canary_ids is None:
            raise MessagesNotSearched
        where.append(Finding.id.in_(_ids("canary", filters.canary_ids)))
    if bound is not None:
        where.append(Finding.id <= bound.max_finding_id)
        where.append(or_(Finding.secret_id.is_(None), Finding.secret_id <= bound.max_secret_id))
    if only is not None:
        where.append(_only(only))
    return where


def _reused(reused: bool, bound: Bound | None) -> ColumnElement[bool]:
    other = aliased(Finding)
    counted = select(other.secret_id).where(other.secret_id.is_not(None))
    if bound is not None:
        counted = counted.where(other.id <= bound.max_finding_id)
    many = counted.group_by(other.secret_id).having(func.count(distinct(other.repository_id)) > 1)
    if reused:
        return Finding.secret_id.in_(many)
    return or_(Finding.secret_id.is_(None), Finding.secret_id.not_in(many))


def _totals_of_subjects(within: Any) -> Any:
    other = aliased(Finding)
    return (
        select(
            other.secret_id.label("secret_id"),
            func.count().label("findings"),
            func.count(distinct(other.repository_id)).label("repos"),
            func.min(other.tool).label("first_tool"),
            *(
                func.max(case((other.tool == tool, 1), else_=0)).label(name)
                for tool, name in _TOOL_FLAGS.items()
            ),
        )
        .where(other.secret_id.in_(within))
        .group_by(other.secret_id)
        .subquery("totals")
    )


def _held_by(matching: CTE) -> Any:
    return select(matching.c.secret_id).where(matching.c.secret_id.is_not(None))


def _sorted_by_counts(sort: ListSort, view: View) -> bool:
    if view is View.ALL:
        return sort is ListSort.REPOS
    return sort in (ListSort.FINDINGS, ListSort.REPOS, ListSort.TOOL)


def _matching(
    filters: Filters,
    *,
    view: View,
    bound: Bound | None = None,
    only: Collection[Subject] | None = None,
) -> CTE:
    kind = func.coalesce(Secret.kind, Finding.rule)
    status = func.coalesce(Secret.status, Finding.status)
    return (
        select(
            Finding.id,
            Finding.secret_id,
            func.coalesce(Finding.secret_id, -Finding.id).label("subject_key"),
            Finding.repository_id,
            Repository.org,
            Repository.name.label("repo_name"),
            Repository.display_path.label("repo_path"),
            Repository.kind.label("repo_kind"),
            Finding.display_path,
            Finding.commit,
            Finding.authored_at,
            Finding.tool,
            kind.label("kind"),
            status.label("status"),
            case(_STATUS_RANK, value=status).label("status_rank"),
        )
        .select_from(Finding)
        .join(Repository, Repository.id == Finding.repository_id)
        .outerjoin(Secret, Secret.id == Finding.secret_id)
        .where(*_conditions(filters, view, kind, status, bound, only))
        .cte("m")
    )


def _rows(matching: CTE, view: View, *, counted: bool) -> CTE:
    m = matching.c
    if view is View.ALL:
        if not counted:
            return select(
                matching,
                literal(1).label("findings"),
                literal(1).label("repos"),
                m.tool.label("first_tool"),
                *(
                    case((m.tool == tool, 1), else_=0).label(name)
                    for tool, name in _TOOL_FLAGS.items()
                ),
            ).cte("listed")
        totals = _totals_of_subjects(_held_by(matching))
        return (
            select(
                matching,
                literal(1).label("findings"),
                func.coalesce(totals.c.repos, 1).label("repos"),
                m.tool.label("first_tool"),
                *(
                    case((m.tool == tool, 1), else_=0).label(name)
                    for tool, name in _TOOL_FLAGS.items()
                ),
            )
            .select_from(matching.outerjoin(totals, totals.c.secret_id == m.secret_id))
            .cte("listed")
        )
    ranked = select(
        matching,
        func.row_number()
        .over(partition_by=m.subject_key, order_by=(m.authored_at.asc().nulls_last(), m.id))
        .label("rn"),
    ).cte("ranked")
    r = ranked.c
    kept = [column for column in ranked.c if column.name != "rn"]
    if not counted:
        return (
            select(
                *kept,
                literal(1).label("findings"),
                literal(1).label("repos"),
                r.tool.label("first_tool"),
                *(
                    case((r.tool == tool, 1), else_=0).label(name)
                    for tool, name in _TOOL_FLAGS.items()
                ),
            )
            .where(r.rn == 1)
            .cte("listed")
        )
    totals = _totals_of_subjects(_held_by(matching))
    return (
        select(
            *kept,
            func.coalesce(totals.c.findings, 1).label("findings"),
            func.coalesce(totals.c.repos, 1).label("repos"),
            func.coalesce(totals.c.first_tool, r.tool).label("first_tool"),
            *(
                func.coalesce(totals.c[name], case((r.tool == tool, 1), else_=0)).label(name)
                for tool, name in _TOOL_FLAGS.items()
            ),
        )
        .select_from(ranked.outerjoin(totals, totals.c.secret_id == r.secret_id))
        .where(r.rn == 1)
        .cte("listed")
    )


def _with_counts(
    session: Session, view: View, found: Sequence[Mapping[Any, Any]]
) -> list[dict[str, Any]]:
    rows = [dict(row) for row in found]
    held = sorted({row["secret_id"] for row in rows if row["secret_id"] is not None})
    if not held:
        return rows
    totals = _totals_of_subjects(_ids("counted", held))
    counts = {each["secret_id"]: each for each in session.execute(select(totals)).mappings()}
    for row in rows:
        each = counts.get(row["secret_id"])
        if each is None:
            continue
        row["repos"] = each["repos"]
        if view is View.UNIQUE:
            row["findings"] = each["findings"]
            row["first_tool"] = each["first_tool"]
            for name in _TOOL_FLAGS.values():
                row[name] = each[name]
    return rows


def _ordering(rows: CTE, sort: ListSort, order: Order) -> list[UnaryExpression[Any]]:
    keys = [rows.c[_SORT_COLUMN[sort]], rows.c.id]
    ordering = [key.desc() if order == "desc" else key.asc() for key in keys]
    if sort in (ListSort.DATE, ListSort.ORG):
        ordering[0] = ordering[0].nulls_last()
    return ordering


def _subject(secret_id: int | None, finding_id: int) -> Subject:
    if secret_id is None:
        return Subject(SubjectKind.FINDING, finding_id)
    return Subject(SubjectKind.SECRET, secret_id)


def _no_longer_reported(
    session: Session, view: View, found: Sequence[Mapping[Any, Any]]
) -> list[bool]:
    anchors = {row["id"] for row in found}
    seen = set(
        session.scalars(current_sighting().where(Sighting.finding_id.in_(_ids("seen", anchors))))
    )
    if view is View.ALL:
        return [row["id"] not in seen for row in found]
    held = {row["secret_id"] for row in found if row["secret_id"] is not None}
    secrets = set(
        session.scalars(
            select(Finding.secret_id)
            .join(Sighting, Sighting.finding_id == Finding.id)
            .join(ToolRun, ToolRun.id == Sighting.tool_run_id)
            .where(Finding.secret_id.in_(_ids("held", held)), ToolRun.superseded_at.is_(None))
        )
    )
    return [
        row["id"] not in seen if row["secret_id"] is None else row["secret_id"] not in secrets
        for row in found
    ]


def _reported_live(session: Session, view: View, found: Sequence[Mapping[Any, Any]]) -> list[bool]:
    anchors = {row["id"] for row in found}
    live = set(
        session.scalars(live_sighting().where(Sighting.finding_id.in_(_ids("live", anchors))))
    )
    if view is View.ALL:
        return [row["id"] in live for row in found]
    held = {row["secret_id"] for row in found if row["secret_id"] is not None}
    secrets = set(
        session.scalars(
            select(Finding.secret_id)
            .join(Sighting, Sighting.finding_id == Finding.id)
            .join(ToolRun, ToolRun.id == Sighting.tool_run_id)
            .where(
                Finding.secret_id.in_(_ids("live_held", held)),
                ToolRun.superseded_at.is_(None),
                Sighting.reported_live.is_(True),
            )
        )
    )
    return [
        row["id"] in live if row["secret_id"] is None else row["secret_id"] in secrets
        for row in found
    ]


def _rows_of(session: Session, view: View, found: Sequence[Mapping[Any, Any]]) -> list[Row]:
    return [
        _row(each, marked, live)
        for each, marked, live in zip(
            found,
            _no_longer_reported(session, view, found),
            _reported_live(session, view, found),
            strict=True,
        )
    ]


def _row(found: Mapping[Any, Any], no_longer_reported: bool, reported_live: bool) -> Row:
    return Row(
        subject=_subject(found["secret_id"], found["id"]),
        anchor_finding_id=found["id"],
        repository_id=found["repository_id"],
        org=found["org"],
        repo_name=found["repo_name"],
        display_path=found["display_path"],
        commit=found["commit"],
        authored_at=found["authored_at"],
        kind=found["kind"],
        tools=tuple(sorted(tool for tool, name in _TOOL_FLAGS.items() if found[name])),
        status=found["status"],
        findings=found["findings"],
        repos=found["repos"],
        no_longer_reported=no_longer_reported,
        reported_live=reported_live,
        repository_on_disk=found["repo_kind"] is not RepositoryKind.NOT_ON_DISK,
    )


def matching(filters: Filters, *, view: View, only: Collection[Subject] | None = None) -> CTE:
    return _matching(filters, view=view, only=only)


def totals(session: Session, matching: CTE) -> tuple[int, int]:
    return _totals(session, matching)


def grouped(
    session: Session,
    matching: CTE,
    column: ColumnElement[Any],
    *,
    label: ColumnElement[Any] | None = None,
    limit: int | None = None,
) -> tuple[list[Group], int]:
    keys = [column] if label is None else [column, label]
    ordered = (
        select(
            *keys,
            func.count().label("findings"),
            func.count(distinct(matching.c.subject_key)).label("unique"),
            func.count().over().label("groups"),
        )
        .select_from(matching)
        .group_by(*keys)
        .order_by(func.count().desc(), column)
    )
    if limit is not None:
        ordered = ordered.limit(limit)
    rows = session.execute(ordered).all()
    found = [
        Group(
            key=row[0],
            label=None if label is None else row[1],
            findings=int(row.findings),
            unique=int(row.unique),
        )
        for row in rows
    ]
    return found, int(rows[0].groups) if rows else 0


def _totals(session: Session, matching: CTE) -> tuple[int, int]:
    m = matching.c
    findings, unique = session.execute(
        select(
            func.count(),
            func.count(distinct(m.secret_id)) + func.count().filter(m.secret_id.is_(None)),
        ).select_from(matching)
    ).one()
    return int(findings), int(unique)


def reported_mark(session: Session) -> ReportedMark:
    removed = session.scalar(
        select(func.count()).select_from(Import).where(Import.state == ImportState.REMOVED)
    )
    sightings, live = session.execute(
        select(func.count(), func.count().filter(Sighting.reported_live.is_(True))).select_from(
            Sighting
        )
    ).one()
    superseded = session.scalar(
        select(func.count()).select_from(ToolRun).where(ToolRun.superseded_at.is_not(None))
    )
    deleted = session.scalar(
        select(func.coalesce(func.sum(func.json_extract(Deletion.counts, "$.findings")), 0))
    )
    return ReportedMark(
        removed_imports=removed or 0,
        deleted_findings=int(deleted or 0),
        superseded_runs=superseded or 0,
        sightings=int(sightings),
        live_sightings=int(live),
    )


def names_reported(filters: Filters) -> bool:
    return filters.reported is not ReportedScope.ALL or filters.reported_live is not None


def _bound(session: Session, filters: Filters) -> Bound:
    scan_ended = None
    if filters.scan_id is not None:
        state = session.scalar(select(Scan.state).where(Scan.id == filters.scan_id))
        scan_ended = state in ENDED_SCAN
    return Bound(
        max_secret_id=session.scalar(select(func.max(Secret.id))) or 0,
        max_finding_id=session.scalar(select(func.max(Finding.id))) or 0,
        scan_ended=scan_ended,
        reported_mark=reported_mark(session) if names_reported(filters) else None,
    )


def clamped(page: int, per_page: int, *, most: int = MAX_PER_PAGE) -> tuple[int, int]:
    return max(1, min(page, MAX_PAGE)), max(1, min(per_page, most))


def list_page(
    session: Session,
    filters: Filters,
    *,
    view: View,
    sort: ListSort,
    order: Order,
    page: int,
    per_page: int,
    only: Collection[Subject] | None = None,
    summary: bool = True,
) -> ListPage:
    if sort not in _SORT_COLUMN:
        raise ValueError(f"the list cannot sort by {sort.value} here: it orders opened values")
    page, per_page = clamped(page, per_page, most=LIST_MAX_PER_PAGE)
    counted = _sorted_by_counts(sort, view)
    rows = _rows(_matching(filters, view=view, only=only), view, counted=counted)
    found: Sequence[Mapping[Any, Any]] = list(
        session.execute(
            select(rows)
            .order_by(*_ordering(rows, sort, order))
            .limit(per_page)
            .offset((page - 1) * per_page)
        ).mappings()
    )
    if not counted:
        found = _with_counts(session, view, found)
    listed = _rows_of(session, view, found)
    summarised = page_summary(session, filters, view=view, only=only, summary=summary)
    return replace(summarised, rows=listed)


def all_rows(
    session: Session,
    filters: Filters,
    *,
    view: View,
    sort: ListSort,
    order: Order,
    only: Collection[Subject] | None = None,
) -> list[Row]:
    if sort not in _SORT_COLUMN:
        raise ValueError(f"the list cannot sort by {sort.value} here: it orders opened values")
    rows = _rows(_matching(filters, view=view, only=only), view, counted=True)
    found = session.execute(select(rows).order_by(*_ordering(rows, sort, order))).mappings()
    return _rows_of(session, view, list(found))


def first_places(
    session: Session, filters: Filters, *, only: Collection[Subject] | None = None
) -> list[tuple[Subject, int]]:
    m = _matching(filters, view=View.UNIQUE, only=only)
    ranked = select(
        m.c.secret_id,
        m.c.id,
        func.row_number()
        .over(
            partition_by=(m.c.subject_key, m.c.repository_id),
            order_by=(m.c.authored_at.asc().nulls_last(), m.c.id),
        )
        .label("rn"),
    ).subquery()
    found = session.execute(
        select(ranked.c.secret_id, ranked.c.id).where(ranked.c.rn == 1).order_by(ranked.c.id)
    )
    return [(_subject(secret_id, finding_id), finding_id) for secret_id, finding_id in found]


def page_summary(
    session: Session,
    filters: Filters,
    *,
    view: View,
    only: Collection[Subject] | None = None,
    summary: bool = True,
) -> ListPage:
    if not summary:
        return ListPage(
            rows=[],
            total_findings=None,
            total_unique=None,
            bound=_bound(session, filters),
            last_change_id=latest_change_id(session),
        )
    found = _matching(filters, view=view, only=only)
    total_findings, total_unique = _totals(session, found)
    any_status = replace(filters, statuses=(), statuses_negated=False)
    statused = found if any_status == filters else _matching(any_status, view=view, only=only)
    return ListPage(
        rows=[],
        total_findings=total_findings,
        total_unique=total_unique,
        bound=_bound(session, filters),
        last_change_id=latest_change_id(session),
        by_status=grouped(session, statused, statused.c.status)[0],
        by_tool=grouped(session, found, found.c.tool)[0],
    )


def matching_subjects(
    session: Session,
    filters: Filters,
    *,
    view: View,
    bound: Bound | None = None,
    only: Collection[Subject] | None = None,
) -> list[Subject]:
    matching = _matching(filters, view=view, bound=bound, only=only)
    keys = session.scalars(select(matching.c.subject_key).distinct())
    return sorted(
        Subject(SubjectKind.SECRET, key) if key > 0 else Subject(SubjectKind.FINDING, -key)
        for key in keys
    )


def rows_for(
    session: Session, filters: Filters, *, view: View, subjects: Sequence[Subject]
) -> list[Row]:
    if not subjects:
        return []
    rows = _rows(_matching(filters, view=view, only=subjects), view, counted=True)
    found = session.execute(
        select(rows).order_by(rows.c.authored_at.asc().nulls_last(), rows.c.id)
    ).mappings()
    place: dict[Subject, int] = {}
    for n, subject in enumerate(subjects):
        place.setdefault(subject, n)
    return sorted(_rows_of(session, view, list(found)), key=lambda row: place[row.subject])


def latest_change_id(session: Session) -> int:
    return session.scalar(select(func.max(StatusChange.id))) or 0


def path_choices(session: Session, repository_ids: Collection[int], text: str) -> list[PathChoice]:
    subject = func.coalesce(Finding.secret_id, -Finding.id)
    query = select(
        Finding.display_path, func.count().label("findings"), func.count(distinct(subject))
    )
    if repository_ids:
        query = query.where(Finding.repository_id.in_(sorted(set(repository_ids))))
    if text:
        query = query.where(Finding.display_path.ilike(like.anywhere(text), escape=like.ESCAPE))
    query = (
        query.group_by(Finding.display_path)
        .order_by(func.count().desc(), Finding.display_path)
        .limit(MAX_PATH_CHOICES)
    )
    return [
        PathChoice(path=path, findings=findings, unique=unique)
        for path, findings, unique in session.execute(query)
    ]


def facets(session: Session) -> Facets:
    scans = session.execute(
        select(Scan.id, Scan.created_at, Scan.state).order_by(Scan.id.desc()).limit(MAX_FACET_SCANS)
    )
    return Facets(
        tools=sorted(session.scalars(select(Finding.tool).distinct())),
        scans=[(scan_id, created_at, state) for scan_id, created_at, state in scans],
    )


def choices(
    session: Session, dimension: ChoiceDimension, text: str, *, ids: Collection[int] = ()
) -> list[Choice]:
    subject = func.coalesce(Finding.secret_id, -Finding.id)
    counted = (func.count().label("findings"), func.count(distinct(subject)).label("unique"))
    query: Any
    searched: Any
    if dimension is ChoiceDimension.REPOSITORY:
        query = (
            select(Repository.id, Repository.display_path, *counted)
            .join(Finding, Finding.repository_id == Repository.id)
            .group_by(Repository.id)
        )
        if ids:
            query = query.where(Repository.id.in_(sorted(set(ids))))
        searched = Repository.display_path
    elif dimension is ChoiceDimension.ORG:
        query = (
            select(Repository.org, Repository.org, *counted)
            .join(Finding, Finding.repository_id == Repository.id)
            .where(Repository.org.is_not(None))
            .group_by(Repository.org)
        )
        searched = Repository.org
    else:
        kind = func.coalesce(Secret.kind, Finding.rule)
        query = (
            select(kind, kind, *counted)
            .select_from(Finding)
            .outerjoin(Secret, Secret.id == Finding.secret_id)
            .group_by(kind)
        )
        searched = kind
    if text:
        query = query.where(searched.ilike(like.anywhere(text), escape=like.ESCAPE))
    query = query.order_by(func.count().desc(), searched).limit(
        max(MAX_CHOICES, len(ids)) if ids else MAX_CHOICES
    )
    found = [
        Choice(value=value, label=label, findings=findings, unique=unique)
        for value, label, findings, unique in session.execute(query)
    ]
    if dimension is ChoiceDimension.ORG and (
        not text or text.casefold() in NO_ORG_LABEL.casefold()
    ):
        found = _no_org(session, counted) + found
    return found


def _no_org(session: Session, counted: tuple[Any, ...]) -> list[Choice]:
    findings, unique = session.execute(
        select(*counted)
        .select_from(Finding)
        .join(Repository, Repository.id == Finding.repository_id)
        .where(Repository.org.is_(None))
    ).one()
    if findings == 0:
        return []
    return [Choice(value=NO_ORG, label=NO_ORG_LABEL, findings=findings, unique=unique)]
