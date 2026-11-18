from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Dialect,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected: timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat(timespec="microseconds")

    def process_result_value(self, value: str | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value).astimezone(UTC)


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            native_enum=False,
            create_constraint=False,
            length=16,
            values_callable=lambda roles: [r.value for r in roles],
        )
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    session_epoch: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("0")
    )


class LoginThrottle(Base):
    __tablename__ = "login_throttle"

    key_hmac: Mapped[str] = mapped_column(String(64), primary_key=True)
    failed_count: Mapped[int] = mapped_column(Integer)
    first_failed_at: Mapped[datetime] = mapped_column(UTCDateTime)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class RememberedDevice(Base):
    __tablename__ = "remembered_devices"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    key_hmac: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime] = mapped_column(UTCDateTime)


type AuditValue = str | int | float | bool | list[AuditValue] | dict[str, AuditValue] | None


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    ip: Mapped[str | None] = mapped_column(String(45), default=None)
    detail: Mapped[dict[str, AuditValue]] = mapped_column(JSON, default=dict)


class ToolName(StrEnum):
    GIT_SECRETS = "git-secrets"
    GITLEAKS = "gitleaks"
    TRUFFLEHOG = "trufflehog"
    CUSTOM_RULES = "custom-rules"


class RepositoryKind(StrEnum):
    WORK_TREE = "work_tree"
    BARE = "bare"
    NOT_ON_DISK = "not_on_disk"
    UPLOADED = "uploaded"


class RepositoryState(StrEnum):
    SCANNABLE = "scannable"
    REFUSED = "refused"
    MISSING = "missing"


class RepositoryRefusal(StrEnum):
    OWN_ALTERNATES = "own_alternates"
    SHA256 = "sha256"
    SHALLOW = "shallow"
    OUTSIDE_ROOT = "outside_root"
    CONFIG_FETCHES = "config_fetches"
    UNREADABLE = "unreadable"


class DeletionState(StrEnum):
    DELETING = "deleting"
    FAILED = "failed"
    DELETED = "deleted"


class DeletionFailure(StrEnum):
    FILES_NOT_DELETED = "files_not_deleted"
    SCANS_STILL_RUNNING = "scans_still_running"
    PLAN_CHANGED = "plan_changed"
    UNEXPECTED_ERROR = "unexpected_error"


class DiscoveryState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ScanKind(StrEnum):
    SCAN = "scan"
    IMPORT = "import"
    REREAD = "reread"


class ScanState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    FINISHED = "finished"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ToolRunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ToolRunFailure(StrEnum):
    OUTSIDE_ROOT = "outside_root"
    SHADOW_REFUSED = "shadow_refused"
    UNREADABLE = "unreadable"
    UNSAFE_WORK_TREE = "unsafe_work_tree"
    UNEXPECTED_OUTPUT = "unexpected_output"
    EXIT_CODE = "exit_code"
    TOOL_UNAVAILABLE = "tool_unavailable"
    UNEXPECTED_ERROR = "unexpected_error"
    INCOMPLETE = "incomplete"
    GIT_INTERRUPTED = "git_interrupted"
    NO_SPACE = "no_space"
    TOOL_REPORTED_ERROR = "tool_reported_error"
    NO_RULES_ENABLED = "no_rules_enabled"
    REPOSITORY_UNAVAILABLE = "repository_unavailable"
    TOOL_CHANGED = "tool_changed"


class IntegrityState(StrEnum):
    NOT_CHECKED = "not_checked"
    VERIFIED = "verified"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class SkipReason(StrEnum):
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    NO_RULES = "no_rules"


class CanaryState(StrEnum):
    SEEN = "seen"
    MISSING = "missing"
    NOT_CHECKED = "not_checked"


class FindingPlace(StrEnum):
    LINE = "line"
    BINARY = "binary"
    MESSAGE = "message"
    UNRESOLVED = "unresolved"
    TAG = "tag"
    OBJECT = "object"
    NAME = "name"


class MetaFrom(StrEnum):
    COMMIT = "commit"
    REPORT = "report"
    NONE = "none"


class KindFrom(StrEnum):
    SCAN = "scan"
    IMPORT = "import"


class SecretStatus(StrEnum):
    UNCLASSIFIED = "unclassified"
    TO_REVIEW = "to_review"
    UNSURE = "unsure"
    VALID = "valid"
    INVALID = "invalid"
    FALSE_POSITIVE = "false_positive"
    TEST_DATA = "test_data"
    REVOKED = "revoked"
    CANARY = "canary"


def _enum[E: StrEnum](cls: type[E]) -> Enum:
    return Enum(
        cls,
        native_enum=False,
        create_constraint=False,
        length=32,
        values_callable=lambda members: [m.value for m in members],
    )


class ScanRoot(Base):
    __tablename__ = "scan_roots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    path: Mapped[str] = mapped_column(String, unique=True)
    added_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


REPOSITORY_PLACE = (
    "(kind = 'not_on_disk' AND scan_root_id IS NULL AND rel_path IS NULL AND git_dir IS NULL)"
    " OR (kind = 'uploaded' AND scan_root_id IS NULL AND rel_path IS NULL"
    " AND git_dir IS NOT NULL)"
    " OR (kind NOT IN ('not_on_disk', 'uploaded') AND scan_root_id IS NOT NULL"
    " AND rel_path IS NOT NULL AND git_dir IS NOT NULL)"
)


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("scan_root_id", "rel_path"),
        CheckConstraint(REPOSITORY_PLACE, name="ck_repositories_not_on_disk_has_no_place"),
        Index(
            "ux_repositories_not_on_disk",
            "org",
            "name",
            unique=True,
            sqlite_where=text("kind = 'not_on_disk'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_root_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_roots.id"), index=True, default=None
    )
    rel_path: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    display_path: Mapped[str] = mapped_column(String)
    org: Mapped[str | None] = mapped_column(String, default=None)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[RepositoryKind] = mapped_column(_enum(RepositoryKind))
    git_dir: Mapped[bytes | None] = mapped_column(LargeBinary, unique=True, default=None)
    state: Mapped[RepositoryState] = mapped_column(_enum(RepositoryState))
    refusal: Mapped[RepositoryRefusal | None] = mapped_column(
        _enum(RepositoryRefusal), default=None
    )
    commit_count: Mapped[int | None] = mapped_column(Integer, default=None)
    size_bytes: Mapped[int] = mapped_column(Integer)
    head: Mapped[str | None] = mapped_column(String, default=None)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    deletion_state: Mapped[DeletionState | None] = mapped_column(_enum(DeletionState), default=None)
    deletion_failure: Mapped[DeletionFailure | None] = mapped_column(
        _enum(DeletionFailure), default=None
    )
    deletion_id: Mapped[int | None] = mapped_column(
        ForeignKey("deletions.id"), index=True, default=None
    )
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_root_id: Mapped[int] = mapped_column(ForeignKey("scan_roots.id"), index=True)
    started_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    state: Mapped[DiscoveryState] = mapped_column(_enum(DiscoveryState))
    found: Mapped[int] = mapped_column(Integer, default=0)
    refused: Mapped[int] = mapped_column(Integer, default=0)
    aliases: Mapped[int] = mapped_column(Integer, default=0)
    not_followed: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    state: Mapped[ScanState] = mapped_column(_enum(ScanState))
    kind: Mapped[ScanKind] = mapped_column(
        _enum(ScanKind), default=ScanKind.SCAN, server_default=ScanKind.SCAN.value
    )
    workers: Mapped[int] = mapped_column(Integer)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    skipped_tools: Mapped[dict[str, str]] = mapped_column(
        JSON, default=dict, server_default=text("'{}'")
    )


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    tool: Mapped[ToolName] = mapped_column(_enum(ToolName))
    identity: Mapped[str] = mapped_column(String)
    state: Mapped[ToolRunState] = mapped_column(_enum(ToolRunState))
    failure: Mapped[ToolRunFailure | None] = mapped_column(_enum(ToolRunFailure), default=None)
    exit_code: Mapped[int | None] = mapped_column(Integer, default=None)
    integrity: Mapped[IntegrityState] = mapped_column(_enum(IntegrityState))
    parse_issues: Mapped[int] = mapped_column(Integer, default=0)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_parts: Mapped[list[str]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    options: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    parser_version: Mapped[int | None] = mapped_column(Integer, default=None)
    canary: Mapped[CanaryState | None] = mapped_column(_enum(CanaryState), default=None)
    canary_commit: Mapped[str | None] = mapped_column(String(40), default=None)
    coverage_gaps: Mapped[dict[str, int] | None] = mapped_column(JSON, default=None)
    diagnosis: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    reread_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_runs.id"), index=True, default=None
    )
    parts_run_id: Mapped[int | None] = mapped_column(ForeignKey("tool_runs.id"), default=None)
    superseded_by_id: Mapped[int | None] = mapped_column(ForeignKey("tool_runs.id"), default=None)
    superseded_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    kept_end: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    binary_sha256: Mapped[str | None] = mapped_column(String(64), default=None)


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value_hash: Mapped[str] = mapped_column(String(64), unique=True)
    value_sealed: Mapped[bytes] = mapped_column(LargeBinary)
    kind: Mapped[str] = mapped_column(String)
    kind_from: Mapped[KindFrom] = mapped_column(
        _enum(KindFrom), default=KindFrom.IMPORT, server_default=KindFrom.IMPORT.value
    )
    status: Mapped[SecretStatus] = mapped_column(
        _enum(SecretStatus),
        default=SecretStatus.UNCLASSIFIED,
        server_default=SecretStatus.UNCLASSIFIED.value,
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "tool", "rule", "commit", "path", "line", "value_hash"),
        Index("ix_findings_secret_repository_tool", "secret_id", "repository_id", "tool"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    tool: Mapped[ToolName] = mapped_column(_enum(ToolName))
    rule: Mapped[str] = mapped_column(String)
    commit: Mapped[str] = mapped_column(String(64))
    path: Mapped[bytes] = mapped_column(LargeBinary)
    display_path: Mapped[str] = mapped_column(String)
    line: Mapped[int] = mapped_column(Integer)
    value_hash: Mapped[str] = mapped_column(String(64))
    value_sealed: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    match_sealed: Mapped[bytes] = mapped_column(LargeBinary)
    secret_id: Mapped[int | None] = mapped_column(
        ForeignKey("secrets.id"), index=True, default=None
    )
    author_name: Mapped[str] = mapped_column(String)
    author_email: Mapped[str] = mapped_column(String)
    authored_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    status: Mapped[SecretStatus | None] = mapped_column(_enum(SecretStatus), default=None)
    message_sealed: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    message_cut: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    place: Mapped[FindingPlace] = mapped_column(
        _enum(FindingPlace), default=FindingPlace.LINE, server_default=FindingPlace.LINE.value
    )
    meta_from: Mapped[MetaFrom] = mapped_column(
        _enum(MetaFrom), default=MetaFrom.REPORT, server_default=MetaFrom.REPORT.value
    )


class Sighting(Base):
    __tablename__ = "sightings"

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    tool_run_id: Mapped[int] = mapped_column(
        ForeignKey("tool_runs.id"), primary_key=True, index=True
    )
    reported_live: Mapped[bool | None] = mapped_column(Boolean, default=None)


class ToolSetting(Base):
    __tablename__ = "tool_settings"

    tool: Mapped[ToolName] = mapped_column(_enum(ToolName), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("1"))
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=1800, server_default="1800")
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, server_default=text("'{}'"))
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class InstanceSetting(Base):
    __tablename__ = "instance_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    scan_workers: Mapped[int] = mapped_column(Integer, default=2, server_default="2")
    upload_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    zip_entries: Mapped[int | None] = mapped_column(Integer, default=None)
    unpacked_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    ratio: Mapped[int | None] = mapped_column(Integer, default=None)
    import_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    key_check: Mapped[str | None] = mapped_column(String(64), default=None)
    canary_words_sealed: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)


class StatusChange(Base):
    __tablename__ = "status_changes"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int | None] = mapped_column(
        ForeignKey("secrets.id"), index=True, default=None
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"), index=True, default=None
    )
    from_status: Mapped[SecretStatus] = mapped_column(_enum(SecretStatus))
    to_status: Mapped[SecretStatus] = mapped_column(_enum(SecretStatus))
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    batch_id: Mapped[str] = mapped_column(String(32))


class Note(Base):
    __tablename__ = "notes"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int | None] = mapped_column(
        ForeignKey("secrets.id"), index=True, default=None
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"), index=True, default=None
    )
    author_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    edited_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    edited_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    text_sealed: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))


class AuditSubject(Base):
    __tablename__ = "audit_event_subjects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(
        ForeignKey("audit_events.id", ondelete="CASCADE"), index=True
    )
    secret_id: Mapped[int | None] = mapped_column(Integer, index=True, default=None)
    finding_id: Mapped[int | None] = mapped_column(Integer, index=True, default=None)


class CustomRule(Base):
    __tablename__ = "custom_rules"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    pattern_sealed: Mapped[bytes] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ImportState(StrEnum):
    UPLOADING = "uploading"
    CHECKING = "checking"
    CHECKED = "checked"
    RECORDING = "recording"
    RECORDED = "recorded"
    DISCARDED = "discarded"
    REMOVED = "removed"
    FAILED = "failed"


class ImportSource(StrEnum):
    UPLOAD = "upload"
    SERVER_FILE = "server_file"


class ImportFailure(StrEnum):
    WRONG_FORMAT = "wrong_format"
    NO_COMMITS = "no_commits"
    HOSTED_SOURCE = "hosted_source"
    TOO_LARGE = "too_large"
    UNREADABLE = "unreadable"
    REPOSITORY_UNAVAILABLE = "repository_unavailable"
    UNEXPECTED_ERROR = "unexpected_error"


class Import(Base):
    __tablename__ = "imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True)
    tool: Mapped[ToolName] = mapped_column(_enum(ToolName))
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    state: Mapped[ImportState] = mapped_column(_enum(ImportState), index=True)
    source: Mapped[ImportSource] = mapped_column(_enum(ImportSource))
    client_name: Mapped[str | None] = mapped_column(String(255), default=None)
    server_path: Mapped[str | None] = mapped_column(String(4096), default=None)
    size_bytes: Mapped[int] = mapped_column(Integer)
    pieces: Mapped[int] = mapped_column(Integer)
    pieces_received: Mapped[int] = mapped_column(Integer, default=0)
    check: Mapped[dict[str, int] | None] = mapped_column(JSON, default=None)
    failure: Mapped[ImportFailure | None] = mapped_column(_enum(ImportFailure), default=None)
    failure_reason: Mapped[str | None] = mapped_column(String(128), default=None)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    recorded_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    removed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class UploadState(StrEnum):
    UPLOADING = "uploading"
    QUEUED = "queued"
    PROCESSING = "processing"
    WAITING = "waiting"
    DONE = "done"
    FAILED = "failed"
    DISCARDED = "discarded"


class UploadFailure(StrEnum):
    NOT_A_ZIP = "not_a_zip"
    MULTI_DISK = "multi_disk"
    TRUNCATED = "truncated"
    TOO_MANY_ENTRIES = "too_many_entries"
    TOO_LARGE_UNPACKED = "too_large_unpacked"
    OVERLAPPING = "overlapping"
    BACKSLASH_NAMES = "backslash_names"
    ENCRYPTED = "encrypted"
    BAD_CENTRAL_DIRECTORY = "bad_central_directory"
    LONG_NAMES = "long_names"
    TOO_MANY_REPOSITORIES = "too_many_repositories"
    DISK_FULL = "disk_full"
    NO_REPOS = "no_repos"
    PIECES_UNREADABLE = "pieces_unreadable"
    INTERRUPTED = "interrupted"
    UNEXPECTED_ERROR = "unexpected_error"


class UploadRepoOutcome(StrEnum):
    PENDING = "pending"
    NEW = "new"
    REPLACED = "replaced"
    NEW_VERSION = "new_version"
    WAITING = "waiting"
    ANSWERED = "answered"
    REFUSED = "refused"
    DISCARDED = "discarded"


class UploadRepoRefusal(StrEnum):
    AMBIGUOUS_CASE = "ambiguous_case"
    GIT_FILE_OUTSIDE = "git_file_outside"
    NOT_A_REPO = "not_a_repo"
    BAD_ENTRY_NAME = "bad_entry_name"
    LINK_OR_DEVICE = "link_or_device"
    NAME_COLLISION = "name_collision"
    UNREADABLE = "unreadable"
    TOO_COMPRESSED = "too_compressed"
    SHALLOW = "shallow"
    SHA256 = "sha256"
    PARTIAL_CLONE = "partial_clone"


class Upload(Base):
    __tablename__ = "uploads"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    client_name: Mapped[str] = mapped_column(String(255))
    org_prefix: Mapped[str | None] = mapped_column(String(100), default=None)
    size_bytes: Mapped[int] = mapped_column(Integer)
    last_modified_ms: Mapped[int] = mapped_column(Integer)
    pieces_received: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[UploadState] = mapped_column(_enum(UploadState), index=True)
    failure: Mapped[UploadFailure | None] = mapped_column(_enum(UploadFailure), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), default=None)
    interrupted_runs: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))


class UploadRepo(Base):
    __tablename__ = "upload_repos"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), index=True)
    zip_path: Mapped[str] = mapped_column(String(4096))
    org: Mapped[str | None] = mapped_column(String(100), default=None)
    name: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[UploadRepoOutcome] = mapped_column(_enum(UploadRepoOutcome))
    refusal: Mapped[UploadRepoRefusal | None] = mapped_column(
        _enum(UploadRepoRefusal), default=None
    )
    repository_id: Mapped[int | None] = mapped_column(
        ForeignKey("repositories.id"), index=True, default=None
    )
    candidates: Mapped[list[int]] = mapped_column(JSON, default=list)
    pending_dir: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    placing_dir: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    answered_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    answered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    dropped_objects: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))


class RepositoryVersion(Base):
    __tablename__ = "repository_versions"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    upload_repo_id: Mapped[int] = mapped_column(ForeignKey("upload_repos.id"), unique=True)
    git_dir: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    current: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class DeletionJobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"


class Deletion(Base):
    __tablename__ = "deletions"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    state: Mapped[DeletionJobState] = mapped_column(_enum(DeletionJobState), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    plan_digest: Mapped[str | None] = mapped_column(String(64), default=None)
