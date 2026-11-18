from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    field_validator,
    model_validator,
)

from gitmortem.db.models import AuditValue, FindingPlace, ScanState, SecretStatus, ToolName
from gitmortem.export import ExportFormat
from gitmortem.triage import classify, footprint, notes, query, values
from gitmortem.triage.canary import CanaryField
from gitmortem.triage.context import MarkKind, Unavailable
from gitmortem.triage.query import (
    Bound,
    Filters,
    ListSort,
    ReportedMark,
    ReportedScope,
    ScanScope,
    View,
)
from gitmortem.triage.subjects import Subject, SubjectKind
from gitmortem.triage.values import ValueMode, ValueSearch
from gitmortem.web.schemas import MAX_ID, RowId

MAX_FILTER_ITEMS = 1_000
OrgName = Annotated[str, Field(max_length=4096)]
KindName = Annotated[str, Field(max_length=256)]
PathName = Annotated[str, Field(min_length=1, max_length=query.MAX_PATH_CHARS)]
MaxId = Annotated[int, Field(strict=True, ge=0, le=MAX_ID)]
BatchId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
MAX_OWN_BATCHES = 50
Count = Annotated[int, Field(strict=True, ge=0, le=MAX_ID)]


class SubjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SubjectKind
    id: RowId

    def subject(self) -> Subject:
        return Subject(self.kind, self.id)


class ReportedMarkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    removed_imports: Count
    deleted_findings: Count
    superseded_runs: Count
    sightings: Count
    live_sightings: Count


class BoundIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_secret_id: MaxId
    max_finding_id: MaxId
    scan_ended: bool | None = Field(default=None, strict=True)
    reported_mark: ReportedMarkIn | None = None

    def bound(self) -> Bound:
        mark = self.reported_mark
        return Bound(
            max_secret_id=self.max_secret_id,
            max_finding_id=self.max_finding_id,
            scan_ended=self.scan_ended,
            reported_mark=(
                None
                if mark is None
                else ReportedMark(
                    mark.removed_imports,
                    mark.deleted_findings,
                    mark.superseded_runs,
                    mark.sightings,
                    mark.live_sightings,
                )
            ),
        )


def _each_once(subjects: list[SubjectIn]) -> list[SubjectIn]:
    if len({(s.kind, s.id) for s in subjects}) != len(subjects):
        raise ValueError("a subject is named more than once")
    return subjects


class FiltersIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    orgs: list[OrgName] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    repository_ids: list[RowId] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    paths: list[PathName] = Field(default_factory=list, max_length=query.MAX_PATHS)
    kinds: list[KindName] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    kinds_negated: bool = Field(default=False, strict=True)
    tools: list[ToolName] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    statuses: list[SecretStatus] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    statuses_negated: bool = Field(default=False, strict=True)
    authored_from: AwareDatetime | None = None
    authored_to: AwareDatetime | None = None
    scan_id: RowId | None = None
    scan_scope: ScanScope = ScanScope.SEEN
    reported: ReportedScope = ReportedScope.ALL
    reported_live: bool | None = Field(default=None, strict=True)
    reused: bool | None = Field(default=None, strict=True)
    no_org: bool = Field(default=False, strict=True)
    text: str | None = Field(default=None, max_length=query.MAX_TEXT, repr=False)
    canary: bool = Field(default=False, strict=True)

    def filters(self) -> Filters:
        return Filters(
            orgs=tuple(self.orgs),
            repository_ids=tuple(self.repository_ids),
            paths=tuple(dict.fromkeys(self.paths)),
            kinds=tuple(self.kinds),
            kinds_negated=self.kinds_negated,
            tools=tuple(self.tools),
            statuses=tuple(self.statuses),
            statuses_negated=self.statuses_negated,
            authored_from=self.authored_from,
            authored_to=self.authored_to,
            scan_id=self.scan_id,
            scan_scope=self.scan_scope,
            reported=self.reported,
            reported_live=self.reported_live,
            reused=self.reused,
            no_org=self.no_org,
            text=self.text,
            canary=self.canary,
        )


class ValueSearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=values.MAX_SEARCH_CHARS, repr=False)
    mode: Literal[ValueMode.EXACT, ValueMode.PARTIAL]

    @model_validator(mode="after")
    def _partial_is_long_enough(self) -> Self:
        if self.mode is ValueMode.PARTIAL and len(self.text) < values.MIN_PARTIAL:
            raise ValueError(
                f"a partial value search needs at least {values.MIN_PARTIAL} characters"
            )
        return self

    def search(self) -> ValueSearch:
        return ValueSearch(text=self.text, mode=self.mode)


class ListQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    filters: FiltersIn = Field(default_factory=FiltersIn)
    view: View = View.UNIQUE
    sort: ListSort = ListSort.DATE
    order: Literal["asc", "desc"] = "desc"
    page: int = Field(default=1, strict=True, ge=1, le=query.MAX_PAGE)
    per_page: int = Field(default=50, strict=True, ge=1, le=query.LIST_MAX_PER_PAGE)
    value_search: ValueSearchIn | None = None
    summary: bool = Field(default=True, strict=True)

    @model_validator(mode="after")
    def _value_sort_is_unique(self) -> Self:
        if self.sort is ListSort.VALUE and self.view is View.ALL:
            raise ValueError("the list can be sorted by value only in the unique view")
        return self


class RowOut(BaseModel):
    kind: SubjectKind
    id: int
    anchor_finding_id: int
    repository_id: int
    org: str | None
    repo_name: str
    display_path: str
    commit: str
    authored_at: datetime | None
    kind_label: str
    tools: list[ToolName]
    status: SecretStatus
    findings: int
    repos: int
    no_longer_reported: bool
    reported_live: bool
    repository_on_disk: bool
    value: str = Field(repr=False)


class ReportedMarkOut(BaseModel):
    removed_imports: int
    deleted_findings: int
    superseded_runs: int
    sightings: int
    live_sightings: int


class BoundOut(BaseModel):
    max_secret_id: int
    max_finding_id: int
    scan_ended: bool | None
    reported_mark: ReportedMarkOut | None


class ListOut(BaseModel):
    items: list[RowOut]
    page: int
    per_page: int
    total_findings: int | None
    total_unique: int | None
    bound: BoundOut
    last_change_id: int
    by_status: list["GroupOut"] | None
    by_tool: list["GroupOut"] | None


class CanariesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subjects: list[SubjectIn] = Field(min_length=1, max_length=query.LIST_MAX_PER_PAGE)


class CanarySubjectOut(BaseModel):
    kind: SubjectKind
    id: int


class CanariesOut(BaseModel):
    possible: list[CanarySubjectOut]
    unchecked: bool


class GroupOut(BaseModel):
    key: str | int | None
    label: str | None
    findings: int
    unique: int


class GroupsOut(BaseModel):
    groups: list[GroupOut]
    total_groups: int


class StatsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    filters: FiltersIn = Field(default_factory=FiltersIn)
    view: View = View.UNIQUE
    value_search: ValueSearchIn | None = None


class ExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    filters: FiltersIn = Field(default_factory=FiltersIn)
    view: View = View.UNIQUE
    sort: ListSort = ListSort.DATE
    order: Literal["asc", "desc"] = "desc"
    value_search: ValueSearchIn | None = None
    format: ExportFormat
    include_values: bool = Field(default=True, strict=True)

    @model_validator(mode="after")
    def _value_sort_is_unique(self) -> Self:
        if self.sort is ListSort.VALUE and self.view is View.ALL:
            raise ValueError("an export can be sorted by value only in the unique view")
        return self


class StatsOut(BaseModel):
    findings: int
    unique: int
    by_org: GroupsOut
    by_repository: GroupsOut
    by_kind: GroupsOut
    by_status: GroupsOut
    by_tool: GroupsOut


class FacetScanOut(BaseModel):
    id: int
    created_at: datetime
    state: ScanState


class PathsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    repository_ids: list[RowId] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)
    text: str = Field(default="", max_length=query.MAX_TEXT, repr=False)


class PathChoiceOut(BaseModel):
    path: str
    findings: int
    unique: int


class PathsOut(BaseModel):
    items: list[PathChoiceOut]


class FacetsOut(BaseModel):
    tools: list[ToolName]
    scans: list[FacetScanOut]


class ChoicesIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    dimension: query.ChoiceDimension
    text: str = Field(default="", max_length=query.MAX_TEXT, repr=False)
    ids: list[RowId] = Field(default_factory=list, max_length=MAX_FILTER_ITEMS)

    @model_validator(mode="after")
    def _ids_name_repositories(self) -> Self:
        if self.ids and self.dimension is not query.ChoiceDimension.REPOSITORY:
            raise ValueError("only repositories are named by id")
        return self


class ChoiceOut(BaseModel):
    value: int | str
    label: str
    findings: int
    unique: int


class ChoicesOut(BaseModel):
    items: list[ChoiceOut]


class ValueOut(BaseModel):
    kind: SubjectKind
    id: int
    value: str = Field(repr=False)


class ValuesOut(BaseModel):
    items: list[ValueOut]


class SubjectsTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subjects: list[SubjectIn] = Field(min_length=1, max_length=classify.MAX_SUBJECTS)

    @field_validator("subjects")
    @classmethod
    def _each_once(cls, subjects: list[SubjectIn]) -> list[SubjectIn]:
        return _each_once(subjects)


class MatchingTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: FiltersIn = Field(default_factory=FiltersIn)
    view: View = View.UNIQUE
    value_search: ValueSearchIn | None = None
    bound: BoundIn


class ValuesIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    subjects: list[SubjectIn] | None = Field(default=None, min_length=1)
    matching: MatchingTarget | None = None

    @field_validator("subjects")
    @classmethod
    def _each_once(cls, subjects: list[SubjectIn] | None) -> list[SubjectIn] | None:
        return None if subjects is None else _each_once(subjects)

    @model_validator(mode="after")
    def _one_target(self) -> Self:
        if (self.subjects is None) == (self.matching is None):
            raise ValueError("name subjects or select all matching, one of them")
        return self


def choice_filters(filters: FiltersIn) -> dict[str, AuditValue]:
    chosen: dict[str, AuditValue] = filters.model_dump(
        mode="json", exclude={"text"}, exclude_defaults=True
    )
    return chosen


class StatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    target: SubjectsTarget | MatchingTarget
    status: SecretStatus
    seen_change_id: MaxId
    own_batches: list[BatchId] = Field(default_factory=list, max_length=MAX_OWN_BATCHES)
    note: str | None = Field(default=None, repr=False)
    across_repositories: int | None = Field(default=None, ge=1, le=MAX_ID)

    @field_validator("note")
    @classmethod
    def _clean_note(cls, note: str | None) -> str | None:
        return None if note is None else notes.clean_text(note)


class SkippedOut(BaseModel):
    kind: SubjectKind
    id: int
    status: SecretStatus
    changed_by: str | None
    changed_at: datetime


class StatusOut(BaseModel):
    batch_id: str
    changed: int
    unchanged: int
    skipped: list[SkippedOut]
    skipped_total: int


class HistoryEntryOut(BaseModel):
    at: datetime
    user: str | None
    from_status: SecretStatus
    to_status: SecretStatus
    batch_id: str


class HistoryOut(BaseModel):
    items: list[HistoryEntryOut]


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    text: str = Field(repr=False)

    @field_validator("text")
    @classmethod
    def _clean_text(cls, text: str) -> str:
        return notes.clean_text(text)


class NoteEditIn(NoteIn):
    version: int = Field(ge=0, le=MAX_ID)


class NoteDeleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=0, le=MAX_ID)


class NoteOut(BaseModel):
    id: int
    text: str = Field(repr=False)
    author: str | None
    created_at: datetime
    edited_by: str | None
    edited_at: datetime | None
    version: int


class NoteListOut(BaseModel):
    items: list[NoteOut]


class FindingsQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=query.MAX_PAGE)
    per_page: int = Field(default=50, ge=1, le=query.MAX_PER_PAGE)
    finding: int | None = Field(default=None, ge=1, le=MAX_ID)


class PlaceFindingsQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=query.MAX_PAGE)
    per_page: int = Field(default=50, ge=1, le=query.MAX_PER_PAGE)
    skip: int | None = Field(default=None, ge=0, le=query.MAX_PAGE * query.MAX_PER_PAGE)


class FootprintPlacesQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=query.MAX_PAGE)
    per_page: int = Field(default=20, ge=1, le=footprint.MAX_PLACES_PER_PAGE)
    finding: int | None = Field(default=None, ge=1, le=MAX_ID)


class FootprintPageQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=query.MAX_PAGE)
    per_page: int = Field(default=20, ge=1, le=footprint.MAX_REPOSITORIES_PER_PAGE)


class MarkedSegmentOut(BaseModel):
    text: str = Field(repr=False)
    mark: MarkKind | None


class MessageLineOut(BaseModel):
    segments: list[MarkedSegmentOut]


class FirstSeenOut(BaseModel):
    finding_id: int
    repository_id: int
    repo: str
    display_path: str
    line: int
    commit: str
    authored_at: datetime | None
    author_name: str
    author_email: str
    message_subject: MessageLineOut | None


class CanaryHintOut(BaseModel):
    finding_id: int
    repository_id: int
    repo: str
    commit: str
    display_path: str
    field: CanaryField
    word: str


class SecretOut(BaseModel):
    id: int
    kind: str
    status: SecretStatus
    value: str = Field(repr=False)
    tools: list[ToolName]
    first_seen: FirstSeenOut | None
    findings: int
    repos: int
    last_change_id: int
    marks_dropped: bool
    canary_hints: list[CanaryHintOut]
    canary_hints_more: bool
    canary_unchecked: bool


class FindingItemOut(BaseModel):
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
    commit_message: list[MessageLineOut] | None
    message_cut: bool
    tool: ToolName
    rule: str
    first_seen_at: datetime
    place: FindingPlace
    repository_on_disk: bool
    no_longer_reported: bool
    reported_live: bool


class FindingPageOut(BaseModel):
    items: list[FindingItemOut]
    page: int
    per_page: int
    total: int
    marks_dropped: bool


class FootprintPlaceOut(BaseModel):
    handle: int
    repository_id: int
    repo: str
    org: str | None
    repository_on_disk: bool
    commit: str
    display_path: str
    place: FindingPlace
    line: int
    tools: list[ToolName]
    findings_total: int
    findings: list[FindingItemOut]
    no_longer_reported: bool
    reported_live: bool
    first_authored_at: datetime | None


class FootprintPlacePageOut(BaseModel):
    items: list[FootprintPlaceOut]
    page: int
    per_page: int
    total: int
    holding: int | None
    marks_dropped: bool


class FootprintRepositoryOut(BaseModel):
    repository_id: int
    repo: str
    org: str | None
    repository_on_disk: bool
    places: int
    findings: int
    first_authored_at: datetime | None
    last_authored_at: datetime | None


class FootprintRepositoryPageOut(BaseModel):
    items: list[FootprintRepositoryOut]
    page: int
    per_page: int
    total: int


class FindingOut(FindingItemOut):
    secret_id: int | None
    status: SecretStatus | None
    last_change_id: int | None
    value: str = Field(repr=False)
    marks_dropped: bool
    canary_hints: list[CanaryHintOut]
    canary_hints_more: bool
    canary_unchecked: bool


class ContextLineOut(BaseModel):
    number: int
    segments: list[MarkedSegmentOut]
    is_match: bool
    cut: bool


class ContextLinesOut(BaseModel):
    lines: list[ContextLineOut]
    integrity_failed: bool
    marks_dropped: bool


class ContextUnavailableOut(BaseModel):
    unavailable: Unavailable


class ContextOut(RootModel[ContextLinesOut | ContextUnavailableOut]):
    pass
