import codecs
import hashlib
import os
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, BinaryIO, Protocol

from pydantic import BaseModel, ConfigDict, Field, Strict

from gitmortem.config import tool_file_names
from gitmortem.crypto import RawStore, SealError
from gitmortem.db.models import (
    AuditValue,
    CanaryState,
    FindingPlace,
    IntegrityState,
    MetaFrom,
    RepositoryRefusal,
    ToolName,
    ToolRunFailure,
    ToolRunState,
)
from gitmortem.gitread import MATCH_LIMIT
from gitmortem.gitrun import DISCARD, GitRunner, GitTimeout, NotStarted
from gitmortem.scanning.blob_cache import BlobCache
from gitmortem.scanning.carrier import CARRIER_PART, CarrierMap, load_map
from gitmortem.scanning.options import ToolOptions
from gitmortem.scanning.process import ToolOutputTooLarge, run_tool_process, tool_env
from gitmortem.scanning.repos import WALK_SECONDS, contained_git_dir
from gitmortem.scanning.roots import root_is_usable
from gitmortem.scanning.trace import GitTrace

if TYPE_CHECKING:
    from gitmortem.scanning.rule_patterns import StoredRule
    from gitmortem.scanning.run import Progress

__all__ = [
    "AUTHOR_LIMIT",
    "ERROR_NAME_CHARS",
    "FINDINGS_BATCH",
    "MESSAGE_LIMIT",
    "RULE_LIMIT",
    "UPLOAD_PART",
    "CoverageGaps",
    "Detection",
    "DetectionStatus",
    "ImportTally",
    "ImportedReport",
    "LoadRules",
    "OutputRead",
    "ParsedFinding",
    "Reading",
    "RecordFindings",
    "RunContext",
    "RunDiagnosis",
    "RunOutcome",
    "ToolName",
    "ToolSpec",
    "Verdict",
    "bounded",
    "bounded_bytes",
    "detect_executable",
    "detect_versioned",
    "is_shadowed",
    "recheck_containment",
    "trimmed_value",
    "with_error",
]

UNRECOGNISED_IDENTITY = "unrecognised build"
FINDINGS_BATCH = 500
AUTHOR_LIMIT = 256
MESSAGE_LIMIT = 4096
RULE_LIMIT = 256
UPLOAD_PART = "upload"
_CHUNK = 1 << 16
VERSION_SECONDS = 10.0
VERSION_BYTES = 4096
_NEW_CAPTURE = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
_OPEN_PLAIN = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


class DetectionStatus(StrEnum):
    FOUND = "found"
    UNRECOGNISED = "unrecognised"
    MISSING = "missing"
    NOT_EXECUTABLE = "not_executable"
    SHADOWED = "shadowed"
    UNTESTED = "untested"
    UNSUPPORTED = "unsupported"
    UNSAFE_FOLDER = "unsafe_folder"


@dataclass(frozen=True)
class Detection:
    status: DetectionStatus
    path: Path | None = None
    identity: str | None = None
    sha256: str | None = None
    git_version: str | None = None

    @property
    def usable(self) -> bool:
        return self.status in _USABLE

    def audited(self) -> dict[str, AuditValue]:
        return {
            "status": self.status.value,
            "identity": self.identity,
            "path": None if self.path is None else str(self.path),
            "sha256": self.sha256,
        }


def detection_changes(
    before: Mapping[ToolName, Detection], after: Mapping[ToolName, Detection]
) -> dict[str, AuditValue]:
    changed: dict[str, AuditValue] = {}
    for name in sorted(set(before) | set(after), key=lambda tool: tool.value):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        changed[name.value] = {
            "from": None if old is None else old.audited(),
            "to": None if new is None else new.audited(),
        }
    return changed


_USABLE = frozenset({DetectionStatus.FOUND, DetectionStatus.UNRECOGNISED, DetectionStatus.UNTESTED})


def bounded(text: str, limit: int = AUTHOR_LIMIT) -> str:
    return text.encode("utf-8", "replace")[:limit].decode("utf-8", "ignore")


def bounded_bytes(data: bytes, limit: int) -> bytes:
    if len(data) <= limit:
        return data
    cut = data[:limit]
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    decoder.decode(cut[-3:])
    return cut[: len(cut) - len(decoder.getstate()[0])]


@dataclass(frozen=True)
class ParsedFinding:
    rule: str
    kind: str | None
    commit: str
    path: bytes
    display_path: str
    line: int
    value: bytes | None = field(repr=False)
    matched_line: bytes = field(repr=False)
    author_name: str
    author_email: str
    authored_at: datetime | None
    meta_from: MetaFrom
    commit_message: str | None = field(default=None, repr=False)
    message_cut: bool = False
    place: FindingPlace = FindingPlace.LINE
    reported_live: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule", bounded(self.rule, RULE_LIMIT))
        if self.kind is not None:
            object.__setattr__(self, "kind", bounded(self.kind, RULE_LIMIT))
        object.__setattr__(self, "author_name", bounded(self.author_name))
        object.__setattr__(self, "author_email", bounded(self.author_email))
        object.__setattr__(self, "matched_line", bounded_bytes(self.matched_line, MATCH_LIMIT))
        if self.value is not None:
            object.__setattr__(self, "value", trimmed_value(self.value))
        if self.commit_message is None:
            object.__setattr__(self, "message_cut", False)
            return
        size = len(self.commit_message.encode("utf-8", "replace"))
        object.__setattr__(self, "message_cut", self.message_cut or size > MESSAGE_LIMIT)
        object.__setattr__(self, "commit_message", bounded(self.commit_message, MESSAGE_LIMIT))


def trimmed_value(value: bytes) -> bytes:
    for end in (b"\r\n", b"\n"):
        if value.endswith(end):
            return value[: -len(end)]
    return value


RecordFindings = Callable[[Sequence[ParsedFinding]], None]
LoadRules = Callable[[Sequence[int]], "list[StoredRule]"]

Count = Annotated[int, Strict(), Field(ge=0)]


CENSUS_GAPS = (
    "archives",
    "encoded_text",
    "lfs_pointers",
    "merges_not_read",
    "type_changes",
    "not_carried",
    "records_dropped",
)


class CoverageGaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: Count = 0
    too_large: Count = 0
    long_lines: Count = 0
    unreadable: Count = 0
    rules_left_out: Count = 0
    merges_over_reported: Count = 0
    paths_over_reported: Count = 0
    duplicate_paths: Count = 0
    archives: Count = 0
    encoded_text: Count = 0
    lfs_pointers: Count = 0
    merges_not_read: Count = 0
    type_changes: Count = 0
    not_carried: Count = 0
    records_dropped: Count = 0
    archives_unopened: Count = 0


ERROR_NAME_CHARS = 200


class RunDiagnosis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    git: GitTrace | None = None
    error: Annotated[str, Field(max_length=ERROR_NAME_CHARS)] | None = None


def with_error(stored: Mapping[str, object] | None, error: str) -> dict[str, object]:
    held = RunDiagnosis() if stored is None else RunDiagnosis.model_validate(stored)
    return held.model_copy(update={"error": error}).model_dump(mode="json")


@dataclass
class ImportTally:
    records: int = 0
    uncommitted: int = 0
    hosted: int = 0
    unreadable: int = 0
    redacted: int = 0
    unknown_commits: set[str] = field(default_factory=set)
    refusal: str | None = None


@dataclass(frozen=True)
class ImportedReport:
    part: str
    pieces: int
    tally: ImportTally = field(default_factory=ImportTally, compare=False)


@dataclass(frozen=True)
class Reading:
    runner: GitRunner
    git_dir: Path | None
    raw_store: RawStore
    scan_id: int
    run_id: int
    parts: frozenset[str]
    timeout: float
    cancel: threading.Event
    record: RecordFindings
    progress: "Progress"
    exit_code: int | None = None
    canary_commit: str | None = None
    imported: ImportedReport | None = None
    held: dict[str, CarrierMap | None] = field(default_factory=dict, compare=False, repr=False)
    blobs: BlobCache = field(default_factory=BlobCache, compare=False, repr=False)

    def carrier_map(self) -> CarrierMap | None:
        if CARRIER_PART not in self.held:
            data = b"".join(self.read(CARRIER_PART)) if self.imported is None else b""
            self.held[CARRIER_PART] = load_map(data) if data else None
        return self.held[CARRIER_PART]

    def read(self, part: str) -> Iterator[bytes]:
        if part not in self.parts:
            return
        try:
            if self.imported is None:
                yield from self.raw_store.read(self.scan_id, self.run_id, part)
            elif part == self.imported.part:
                yield from self.raw_store.read_parts(
                    self.scan_id, self.run_id, UPLOAD_PART, self.imported.pieces
                )
        except FileNotFoundError:
            raise SealError from None

    def git_dir_on_disk(self) -> Path:
        if self.git_dir is None:
            raise TypeError("the reading has no git dir")
        return self.git_dir


@dataclass(frozen=True)
class OutputRead:
    whole: bool
    canary_seen: bool = False
    coverage_gaps: CoverageGaps | None = None
    refused: bool = False


@dataclass(frozen=True)
class Verdict:
    state: ToolRunState
    failure: ToolRunFailure | None = None
    canary: CanaryState | None = None
    read: OutputRead | None = None


@dataclass(frozen=True)
class RunContext:
    runner: GitRunner
    git_dir: Path
    root: Path
    bases: tuple[Path, ...]
    data_dir: Path
    key_file: Path | None
    work_dir: Path
    raw_store: RawStore
    scan_id: int
    run_id: int
    timeout: float
    cancel: threading.Event
    tool_path: Path | None
    record: RecordFindings
    progress: "Progress"
    options: ToolOptions
    rules: LoadRules | None = None
    upload_root: Path | None = None
    versions: tuple[Path, ...] = ()
    tool_sha256: str | None = None

    def tool_file(self) -> Path:
        if self.tool_path is None:
            raise TypeError("the run was handed no tool file")
        held = current_sha256(self.tool_path)
        if held is None:
            raise ToolChanged(self.tool_path, ToolRunFailure.TOOL_UNAVAILABLE)
        if held != self.tool_sha256:
            raise ToolChanged(self.tool_path, ToolRunFailure.TOOL_CHANGED)
        return self.tool_path

    def reading(
        self, git_dir: Path, *, exit_code: int | None = None, canary_commit: str | None = None
    ) -> Reading:
        return Reading(
            runner=self.runner,
            git_dir=git_dir,
            raw_store=self.raw_store,
            scan_id=self.scan_id,
            run_id=self.run_id,
            parts=frozenset(self.progress.raw_parts),
            timeout=self.timeout,
            cancel=self.cancel,
            record=self.record,
            progress=self.progress,
            exit_code=exit_code,
            canary_commit=canary_commit,
        )

    def options_as[T: ToolOptions](self, model: type[T]) -> T:
        if not isinstance(self.options, model):
            raise TypeError(
                f"the run was handed {type(self.options).__name__}, not {model.__name__}"
            )
        return self.options


@dataclass(frozen=True)
class RunOutcome:
    state: ToolRunState
    failure: ToolRunFailure | None = None
    exit_code: int | None = None
    integrity: IntegrityState = IntegrityState.NOT_CHECKED
    parse_issues: int = 0
    findings_count: int = 0
    raw_parts: tuple[str, ...] = ()
    parser_version: int | None = None
    canary: CanaryState | None = None
    canary_commit: str | None = None
    coverage_gaps: CoverageGaps | None = None
    diagnosis: RunDiagnosis | None = None


class ToolSpec(Protocol):
    @property
    def name(self) -> ToolName: ...

    @property
    def coverage(self) -> str: ...

    @property
    def offline(self) -> bool: ...

    def detect(
        self,
        path_env: str,
        operator_path: Path | None,
        *,
        known_builds: Mapping[str, str],
        exec_path: Path | None,
        git_version: str | None,
        work_dir: Path,
    ) -> Detection: ...

    @property
    def parser_version(self) -> int: ...

    def run(self, ctx: RunContext) -> RunOutcome: ...

    def read_output(self, reading: Reading) -> OutputRead: ...

    def judge_output(self, reading: Reading) -> Verdict: ...


def _find_on_path(names: Sequence[str], path_env: str) -> Path | None:
    for entry in path_env.split(os.pathsep):
        folder = Path(entry)
        if not entry or not folder.is_absolute():
            continue
        for name in names:
            candidate = folder / name
            if candidate.is_file():
                return candidate
    return None


def _sha256_of(path: Path) -> str | None:
    try:
        fd = os.open(path.resolve(strict=True), _OPEN_PLAIN)
    except (OSError, RuntimeError):
        return None
    with os.fdopen(fd, "rb") as handle:
        return _digest_of(handle)


def _digest_of(handle: BinaryIO) -> str | None:
    digest = hashlib.sha256()
    try:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


class ToolChanged(Exception):
    def __init__(self, path: Path, failure: ToolRunFailure) -> None:
        self.failure = failure
        super().__init__(f"{path} is not the file detection hashed")


_HASHED: dict[tuple[str, int, int, int, int, int], str] = {}
_HASHED_LOCK = threading.Lock()
_HASHED_KEEP = 64
_RACY_NS = 2_000_000_000


def current_sha256(path: Path) -> str | None:
    try:
        fd = os.open(path.resolve(strict=True), _OPEN_PLAIN)
    except (OSError, RuntimeError):
        return None
    with os.fdopen(fd, "rb") as handle:
        try:
            held = os.fstat(handle.fileno())
        except OSError:
            return None
        key = (
            os.fspath(path),
            held.st_dev,
            held.st_ino,
            held.st_size,
            held.st_mtime_ns,
            held.st_ctime_ns,
        )
        with _HASHED_LOCK:
            known = _HASHED.get(key)
        if known is not None:
            return known
        settled = max(held.st_mtime_ns, held.st_ctime_ns) < time.time_ns() - _RACY_NS
        digest = _digest_of(handle)
    if digest is not None and settled:
        with _HASHED_LOCK:
            if len(_HASHED) >= _HASHED_KEEP:
                _HASHED.clear()
            _HASHED[key] = digest
    return digest


def is_shadowed(candidate: Path, exec_path: Path | None, name: str) -> bool:
    if exec_path is None:
        return False
    other = exec_path / name
    try:
        os.lstat(other)
    except OSError:
        return False
    try:
        return not os.path.samestat(os.stat(other), os.stat(candidate))
    except OSError:
        return True


def detect_executable(
    executable: str,
    path_env: str,
    operator_path: Path | None,
    *,
    known_builds: Mapping[str, str],
    exec_path: Path | None,
    git_version: str | None,
) -> Detection:
    candidate = _locate(executable, path_env, operator_path, git_version)
    if isinstance(candidate, Detection):
        return candidate
    digest = _sha256_of(candidate)
    if digest is None:
        return Detection(DetectionStatus.NOT_EXECUTABLE, path=candidate, git_version=git_version)
    release = known_builds.get(digest)
    identity = f"{executable} {release}" if release else UNRECOGNISED_IDENTITY
    if is_shadowed(candidate, exec_path, executable):
        status = DetectionStatus.SHADOWED
    elif release:
        status = DetectionStatus.FOUND
    else:
        status = DetectionStatus.UNRECOGNISED
    return Detection(
        status, path=candidate, identity=identity, sha256=digest, git_version=git_version
    )


def _locate(
    executable: str,
    path_env: str,
    operator_path: Path | None,
    git_version: str | None,
    *,
    windows: bool = os.name == "nt",
) -> Path | Detection:
    names = tool_file_names(ToolName(executable), windows=windows)
    candidate = operator_path or _find_on_path(names, path_env)
    if candidate is None or not candidate.is_file():
        return Detection(DetectionStatus.MISSING, git_version=git_version)
    if not os.access(candidate, os.X_OK):
        return Detection(DetectionStatus.NOT_EXECUTABLE, path=candidate, git_version=git_version)
    return candidate


def detect_versioned(
    executable: str,
    version_args: tuple[str, ...],
    pattern: re.Pattern[str],
    *,
    floor: tuple[int, int, int],
    tested: tuple[int, int, int],
    path_env: str,
    operator_path: Path | None,
    private: Path,
) -> Detection:
    candidate = _locate(executable, path_env, operator_path, git_version=None)
    if isinstance(candidate, Detection):
        return candidate
    digest = _sha256_of(candidate)
    if digest is None:
        return Detection(DetectionStatus.NOT_EXECUTABLE, path=candidate)
    version = _reported_version(executable, candidate, version_args, pattern, private)
    if version is None:
        return Detection(DetectionStatus.UNSUPPORTED, path=candidate, sha256=digest)
    if version == tested:
        status = DetectionStatus.FOUND
    elif version >= floor:
        status = DetectionStatus.UNTESTED
    else:
        status = DetectionStatus.UNSUPPORTED
    identity = f"{executable} {'.'.join(str(part) for part in version)}"
    return Detection(status, path=candidate, identity=identity, sha256=digest)


def _reported_version(
    executable: str,
    tool: Path,
    args: tuple[str, ...],
    pattern: re.Pattern[str],
    private: Path,
) -> tuple[int, int, int] | None:
    out = private / f"{executable}.version"
    fd = os.open(out, _NEW_CAPTURE, 0o600)
    try:
        try:
            code = run_tool_process(
                [str(tool), *args],
                cwd=private,
                env=tool_env(private),
                stdout=fd,
                stderr=DISCARD,
                timeout=VERSION_SECONDS,
                cancel=None,
                max_output=VERSION_BYTES,
            )
        except (GitTimeout, ToolOutputTooLarge, NotStarted):
            return None
        os.lseek(fd, 0, os.SEEK_SET)
        printed = os.read(fd, VERSION_BYTES + 1)
    finally:
        os.close(fd)
        out.unlink(missing_ok=True)
    if code != 0 or len(printed) > VERSION_BYTES:
        return None
    try:
        text = printed.decode("ascii")
    except UnicodeDecodeError:
        return None
    found = pattern.fullmatch(text.strip())
    if found is None:
        return None
    major, minor, patch = found.group(1, 2, 3)
    return int(major), int(minor), int(patch)


def recheck_containment(ctx: RunContext) -> Path | ToolRunFailure:
    if ctx.upload_root is not None:
        return _recheck_upload(ctx, ctx.upload_root)
    if not root_is_usable(ctx.root, bases=ctx.bases, data_dir=ctx.data_dir, key_file=ctx.key_file):
        return ToolRunFailure.OUTSIDE_ROOT
    found = contained_git_dir(
        ctx.git_dir,
        ctx.root,
        skip=(ctx.data_dir,),
        cancel=ctx.cancel,
        deadline=time.monotonic() + WALK_SECONDS,
    )
    if found is RepositoryRefusal.OUTSIDE_ROOT:
        return ToolRunFailure.OUTSIDE_ROOT
    if isinstance(found, RepositoryRefusal):
        return ToolRunFailure.UNREADABLE
    return found


def _recheck_upload(ctx: RunContext, upload_root: Path) -> Path | ToolRunFailure:
    found: list[Path] = []
    for version in ctx.versions or (ctx.git_dir,):
        real = contained_git_dir(
            version,
            upload_root / "repos",
            cancel=ctx.cancel,
            deadline=time.monotonic() + WALK_SECONDS,
        )
        if real is RepositoryRefusal.OUTSIDE_ROOT:
            return ToolRunFailure.OUTSIDE_ROOT
        if isinstance(real, RepositoryRefusal):
            return ToolRunFailure.UNREADABLE
        found.append(real)
    return found[0]
