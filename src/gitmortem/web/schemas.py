from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    RootModel,
    Strict,
    field_validator,
    model_validator,
)

from gitmortem.accounts.audit import MAX_PAGE, MAX_PER_PAGE
from gitmortem.db.models import (
    AuditValue,
    CanaryState,
    DeletionFailure,
    DeletionState,
    DiscoveryState,
    IntegrityState,
    RepositoryKind,
    RepositoryRefusal,
    RepositoryState,
    Role,
    ScanKind,
    ScanState,
    SkipReason,
    ToolName,
    ToolRunFailure,
    ToolRunState,
    UploadRepoOutcome,
)
from gitmortem.deletion.plan import MAX_DELETE_REPOSITORIES, LeftReason
from gitmortem.scanning import progress, repos
from gitmortem.scanning import settings as scan_settings
from gitmortem.scanning.folders import RootState as FolderRootState
from gitmortem.scanning.options import OptionKind, OptionName, OptionValue
from gitmortem.scanning.roots import RootRefusal
from gitmortem.scanning.tools import CoverageGaps, DetectionStatus, RunDiagnosis
from gitmortem.triage import canary
from gitmortem.triage.subjects import SubjectKind

MAX_ID = 9223372036854775807
Username = Annotated[str, Field(max_length=256)]
Password = Annotated[str, Field(max_length=1024)]


class MessageOut(BaseModel):
    message: str


class CsrfOut(BaseModel):
    csrf_token: str


class LoginIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    username: Username
    password: Password = Field(repr=False)


class MeOut(BaseModel):
    id: int
    username: str
    role: Role
    idle_timeout_seconds: int
    must_change_password: bool


class LoginOut(MeOut):
    session_key: str


class SessionKeyOut(BaseModel):
    session_key: str


class PasswordChangeIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    current_password: Password = Field(repr=False)
    new_password: Password = Field(repr=False)


class PasswordConfirmIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    password: Password = Field(repr=False)


class UserOut(BaseModel):
    id: int
    username: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserListOut(RootModel[list[UserOut]]):
    pass


class UserCreateIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    username: Username
    password: Password = Field(repr=False)
    role: Role


class UserUpdateIn(BaseModel):
    role: Role | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def _needs_a_field(self) -> Self:
        if self.role is None and self.is_active is None:
            raise ValueError("send at least one of role and is_active")
        return self


class PasswordResetIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    current_password: Password = Field(repr=False)
    new_password: Password = Field(repr=False)


class AuditQueryIn(BaseModel):
    page: int = Field(default=1, ge=1, le=MAX_PAGE)
    per_page: int = Field(default=50, ge=1, le=MAX_PER_PAGE)


class AuditEventOut(BaseModel):
    id: int
    at: datetime
    action: str
    actor_username: str | None
    target_username: str | None
    ip: str | None
    detail: dict[str, JsonValue]


class AuditPageOut(BaseModel):
    items: list[AuditEventOut]
    page: int
    per_page: int
    total: int


class AuditSubjectOut(BaseModel):
    kind: SubjectKind
    id: int
    kind_label: str
    removed: bool


class AuditSubjectPageOut(BaseModel):
    items: list[AuditSubjectOut]
    page: int
    per_page: int
    total: int


class ScanRootIn(BaseModel):
    path: Annotated[str, Field(max_length=4096)]


class ScanRootOut(BaseModel):
    id: int
    path: str
    usable: bool
    added_by: str | None
    added_at: datetime
    last_discovery_id: int | None


class ScanRootListOut(RootModel[list[ScanRootOut]]):
    pass


class ScanRootBasesOut(BaseModel):
    bases: list[str]


class RootFoldersIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Annotated[str, Field(max_length=4096)] | None = None


class RootFolderOut(BaseModel):
    name: str
    path: str
    readable: bool
    is_repository: bool | None
    repositories: int | None
    repositories_more: bool
    root: FolderRootState
    refusal: RootRefusal | None


class RootFoldersOut(BaseModel):
    path: str | None
    base: str | None
    parent: str | None
    folders: list[RootFolderOut]
    truncated: bool
    partial: bool


class RepositoryQueryIn(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    root: int | None = Field(default=None, ge=1, le=MAX_ID)
    state: RepositoryState | None = None
    kind: RepositoryKind | None = None
    q: str | None = Field(default=None, min_length=1, max_length=repos.MAX_SEARCH_CHARS)
    sort: repos.RepositorySort = repos.RepositorySort.PATH
    order: Literal["asc", "desc"] = "asc"
    page: int = Field(default=1, ge=1, le=repos.MAX_PAGE)
    per_page: int = Field(default=50, ge=1, le=repos.MAX_PER_PAGE)


class RepositoryOut(BaseModel):
    id: int
    scan_root_id: int | None
    display_path: str
    org: str | None
    name: str
    kind: RepositoryKind
    state: RepositoryState
    refusal: RepositoryRefusal | None
    commit_count: int | None
    size_bytes: int
    last_seen_at: datetime
    last_scanned_at: datetime | None = None
    scanning: bool = False
    deletion_state: DeletionState | None = None
    deletion_failure: DeletionFailure | None = None
    versions: list["VersionOut"] | None = None
    updates: int = 0


class VersionOut(BaseModel):
    id: int
    current: bool
    created_at: datetime


class RepositoryIdsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[Annotated[int, Field(strict=True, ge=1, le=MAX_ID)]] = Field(
        min_length=1, max_length=MAX_DELETE_REPOSITORIES
    )


class DeleteRepositoriesIn(RepositoryIdsIn):
    confirm: int = Field(strict=True, ge=1, le=MAX_DELETE_REPOSITORIES)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class LeftFolderOut(BaseModel):
    folder: str
    reason: LeftReason


class DeletionPreviewOut(BaseModel):
    repositories: int
    findings: int
    secrets: int
    with_triage: int
    delete_folders: list[str]
    delete_folders_total: int
    left: list[LeftFolderOut]
    added_nested: list[int]
    digest: str


class DeletionStartedOut(BaseModel):
    deletion_id: int


class UpdateOut(BaseModel):
    upload_id: int
    client_name: str
    at: datetime
    by: str | None
    outcome: UploadRepoOutcome


class UpdatesPageOut(BaseModel):
    items: list[UpdateOut]
    page: int
    per_page: int
    total: int


class RepositoryPageOut(BaseModel):
    items: list[RepositoryOut]
    page: int
    per_page: int
    total: int


class ToolOut(BaseModel):
    name: ToolName
    status: DetectionStatus | None
    identity: str | None
    sha256: str | None
    git_version: str | None
    usable: bool
    enabled: bool
    timeout_seconds: int
    path: str | None
    options: dict[str, OptionValue]
    tested_version: str | None
    enabled_rules: int | None


class ToolListOut(RootModel[list[ToolOut]]):
    pass


OptionValueIn = (
    Annotated[bool, Strict()]
    | Annotated[int, Strict()]
    | Annotated[float, Strict()]
    | list[Annotated[str, Strict()]]
)


class ToolSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: bool | None = Field(default=None, strict=True)
    timeout_seconds: int | None = Field(
        default=None,
        strict=True,
        ge=scan_settings.MIN_TIMEOUT_SECONDS,
        le=scan_settings.MAX_TIMEOUT_SECONDS,
    )
    options: dict[str, OptionValueIn] | None = None

    @model_validator(mode="after")
    def _needs_a_field(self) -> Self:
        if self.enabled is None and self.timeout_seconds is None and self.options is None:
            raise ValueError("send at least one of enabled, timeout_seconds and options")
        return self


class ToolSettingsOut(BaseModel):
    name: ToolName
    enabled: bool
    timeout_seconds: int
    options: dict[str, OptionValue]


class OptionDescriptorOut(BaseModel):
    name: OptionName
    kind: OptionKind
    default: OptionValue
    min: int | float | None = None
    max: int | float | None = None
    choices: list[str] | None = None


class OptionDescriptorListOut(RootModel[list[OptionDescriptorOut]]):
    pass


class ScanSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_workers: int = Field(
        strict=True, ge=scan_settings.MIN_SCAN_WORKERS, le=scan_settings.MAX_SCAN_WORKERS
    )


class ScanSettingsOut(BaseModel):
    scan_workers: int


class UploadLimitsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_bytes: int | None = Field(
        default=None, strict=True, ge=1, le=scan_settings.UPLOAD_BYTES_CEILING
    )
    zip_entries: int | None = Field(
        default=None, strict=True, ge=1, le=scan_settings.ZIP_ENTRIES_CEILING
    )
    unpacked_bytes: int | None = Field(
        default=None, strict=True, ge=1, le=scan_settings.UNPACKED_BYTES_CEILING
    )
    ratio: int | None = Field(default=None, strict=True, ge=1, le=scan_settings.RATIO_CEILING)
    import_bytes: int | None = Field(
        default=None, strict=True, ge=1, le=scan_settings.IMPORT_BYTES_CEILING
    )

    @model_validator(mode="after")
    def _names_one(self) -> "UploadLimitsIn":
        if not self.model_fields_set:
            raise ValueError("name at least one limit")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("a limit is a number, never null")
        return self


class CanaryWordsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    words: list[
        Annotated[str, Field(min_length=canary.MIN_WORD_CHARS, max_length=canary.MAX_WORD_CHARS)]
    ] = Field(max_length=canary.MAX_OWN_WORDS, repr=False)


class CanaryWordsOut(BaseModel):
    built_in: list[str]
    words: list[str] = Field(repr=False)
    most: int
    shortest: int
    longest: int


class UploadLimitValuesOut(BaseModel):
    upload_bytes: int
    zip_entries: int
    unpacked_bytes: int
    ratio: int
    import_bytes: int


class UploadLimitsOut(UploadLimitValuesOut):
    ceilings: UploadLimitValuesOut


MAX_SCAN_REPOSITORIES = 10_000
MAX_SCAN_ROOTS = 100
MAX_REPOSITORY_ORGS = 1_000
RowId = Annotated[int, Field(strict=True, ge=1, le=MAX_ID)]


class RepositoryFiltersIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    text: str = Field(default="", max_length=repos.MAX_SEARCH_CHARS, repr=False)
    orgs: list[Annotated[str, Field(max_length=4096)]] = Field(
        default_factory=list, max_length=MAX_REPOSITORY_ORGS
    )
    no_org: bool = Field(default=False, strict=True)
    kinds: list[RepositoryKind] = Field(default_factory=list, max_length=len(RepositoryKind))
    states: list[RepositoryState] = Field(default_factory=list, max_length=len(RepositoryState))
    scanned: repos.Scanned = repos.Scanned.ANY

    def filters(self) -> repos.RepositoryFilters:
        return repos.RepositoryFilters(
            text=self.text,
            orgs=tuple(dict.fromkeys(self.orgs)),
            no_org=self.no_org,
            kinds=tuple(dict.fromkeys(self.kinds)),
            states=tuple(dict.fromkeys(self.states)),
            scanned=self.scanned,
        )

    def chosen(self) -> dict[str, AuditValue]:
        found: dict[str, AuditValue] = self.model_dump(
            mode="json", exclude={"text"}, exclude_defaults=True
        )
        if self.text:
            found["text_filtered"] = True
        return found


class MatchingRepositoriesIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    scan_root_id: RowId
    filters: RepositoryFiltersIn = Field(default_factory=RepositoryFiltersIn)
    excluded_ids: list[RowId] = Field(default_factory=list, max_length=MAX_SCAN_REPOSITORIES)
    included_ids: list[RowId] = Field(default_factory=list, max_length=MAX_SCAN_REPOSITORIES)

    def matching(self) -> repos.Matching:
        return repos.Matching(
            root_id=self.scan_root_id,
            filters=self.filters.filters(),
            excluded=tuple(dict.fromkeys(self.excluded_ids)),
            included=tuple(dict.fromkeys(self.included_ids)),
        )


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    repository_ids: list[RowId] = Field(default_factory=list, max_length=MAX_SCAN_REPOSITORIES)
    scan_root_ids: list[RowId] = Field(default_factory=list, max_length=MAX_SCAN_ROOTS)
    matching: MatchingRepositoriesIn | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        chosen = [bool(self.repository_ids), bool(self.scan_root_ids), self.matching is not None]
        if chosen.count(True) != 1:
            raise ValueError("send exactly one of repository_ids, scan_root_ids and matching")
        return self


class RepositoryListIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    root: RowId
    filters: RepositoryFiltersIn = Field(default_factory=RepositoryFiltersIn)
    sort: repos.RepositoryListSort = repos.RepositoryListSort.PATH
    order: Literal["asc", "desc"] = "asc"
    page: int = Field(default=1, strict=True, ge=1, le=repos.MAX_PAGE)
    per_page: int = Field(default=50, strict=True, ge=1, le=repos.MAX_LIST_PER_PAGE)


class RepositoryListOut(BaseModel):
    items: list[RepositoryOut]
    page: int
    per_page: int
    total: int
    matching_scannable: int
    root_scannable: int
    root_unscanned: int


class RepositoryOrgsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    root: RowId
    text: str = Field(default="", max_length=repos.MAX_SEARCH_CHARS, repr=False)


class RepositoryOrgOut(BaseModel):
    value: str
    label: str
    repositories: int


class RepositoryOrgsOut(BaseModel):
    items: list[RepositoryOrgOut]


class ScanIdOut(BaseModel):
    scan_id: int


class RereadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stale: bool = Field(strict=True)

    @field_validator("stale")
    @classmethod
    def _only_stale(cls, stale: bool) -> bool:
        if not stale:
            raise ValueError("this route re-reads the runs an older parser judged: stale is true")
        return stale


class RereadOut(BaseModel):
    scan_id: int | None
    runs: int


class DiscoveryIdOut(BaseModel):
    discovery_id: int


class ScanQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=progress.MAX_PAGE)
    per_page: int = Field(default=50, ge=1, le=progress.MAX_PER_PAGE)


class ScanSummaryOut(BaseModel):
    id: int
    kind: ScanKind
    state: ScanState
    started_by: str | None
    workers: int
    run_count: int
    cancel_requested_at: datetime | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanPageOut(BaseModel):
    items: list[ScanSummaryOut]
    page: int
    per_page: int
    total: int


class RunStateCountsOut(BaseModel):
    queued: int
    running: int
    done: int
    failed: int
    timed_out: int
    cancelled: int
    interrupted: int


class IntegrityCountsOut(BaseModel):
    not_checked: int
    verified: int
    failed: int
    timed_out: int


class RunCountsOut(BaseModel):
    states: RunStateCountsOut
    integrity: IntegrityCountsOut


class ToolRunOut(BaseModel):
    id: int
    repository_id: int
    display_path: str
    tool: ToolName
    identity: str
    state: ToolRunState
    failure: ToolRunFailure | None
    exit_code: int | None
    integrity: IntegrityState
    parse_issues: int
    findings_count: int
    coverage_gaps: CoverageGaps | None
    diagnosis: RunDiagnosis | None
    has_output: bool
    canary: CanaryState | None
    kept_end: bool
    reread_of_id: int | None
    superseded_by_id: int | None
    superseded_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None


class ToolRunPageOut(BaseModel):
    items: list[ToolRunOut]
    page: int
    per_page: int
    total: int


class RunOutputOut(BaseModel):
    text: str = Field(repr=False)
    size: int
    cut: bool


class ScanSecretsOut(BaseModel):
    findings: int
    unique: int
    new_unique: int


class ScanOut(ScanSummaryOut):
    counts: RunCountsOut
    skipped_tools: dict[ToolName, SkipReason]
    secrets: ScanSecretsOut


class DiscoveryOut(BaseModel):
    id: int
    scan_root_id: int
    state: DiscoveryState
    found: int
    refused: int
    aliases: int
    not_followed: int
    started_by: str | None
    cancel_requested_at: datetime | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


def described(responses: dict[int, str | dict[str, Any]]) -> Any:
    return responses


def add_model_schemas(spec: dict[Any, Any] | str, models: tuple[type[BaseModel], ...]) -> Any:
    if isinstance(spec, str):
        return spec
    schemas = spec.setdefault("components", {}).setdefault("schemas", {})
    for model in models:
        schema = model.model_json_schema(ref_template="#/components/schemas/{model}", by_alias=True)
        schemas.update(schema.pop("$defs", {}))
        schemas[model.__name__] = schema
    return spec
