import os
import re
import shlex
import sys
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    Strict,
    ValidationError,
    model_validator,
)

from gitmortem.corpus.fakes import SecretType
from gitmortem.crypto import SealError
from gitmortem.db.models import CanaryState, ToolName, ToolRunFailure, ToolRunState
from gitmortem.gitread import MATCH_LIMIT
from gitmortem.gitrun import (
    FILE_CLONE,
    GitCancelled,
    GitError,
    GitRunner,
    GitTimeout,
    NotStarted,
    safe_config,
)
from gitmortem.scanning.canary import CANDIDATES, plant_canary
from gitmortem.scanning.carrier import Census
from gitmortem.scanning.options import TruffleHogOptions, no_rules
from gitmortem.scanning.places import ReportedPlace
from gitmortem.scanning.process import (
    ToolEnv,
    ToolOutputTooLarge,
    never_made,
    run_tool_process,
    tool_env,
    watched_space,
)
from gitmortem.scanning.run import (
    HOSTED,
    UNCOMMITTED,
    Hosted,
    Progress,
    Recorder,
    Reported,
    ReportedCommit,
    RunDirs,
    Uncommitted,
    census_gaps,
    finished,
    make_run_dirs,
    prepare_shadow,
    ran_whole,
    read_findings,
    record_reported,
    remove_run_dirs,
    seal_parts,
    tallied,
)
from gitmortem.scanning.streams import cut_to, json_lines, line_heads, within_bytes
from gitmortem.scanning.tools import (
    RULE_LIMIT,
    CoverageGaps,
    Detection,
    OutputRead,
    Reading,
    RunContext,
    RunOutcome,
    ToolChanged,
    Verdict,
    bounded_bytes,
    detect_versioned,
    recheck_containment,
    trimmed_value,
)
from gitmortem.scanning.trace import trace_dir

__all__ = [
    "PARSER_VERSION",
    "REPLACEMENT",
    "TEMPLATE_KEYS",
    "NoDetectorsEnabled",
    "TruffleHogRecord",
    "TruffleHogSpec",
    "canary_keeps",
    "invocation",
    "judge_results",
    "logged_error",
    "parse_results",
    "read_results",
    "reported_values",
    "run_env",
    "shadow_uri",
    "template_config",
    "write_template",
]

PARSER_VERSION = 2
FLOOR = (3, 99, 7)
TESTED = (3, 99, 7)
VERSION = re.compile(r"trufflehog (\d+)\.(\d+)\.(\d+)")
VERSION_ARGS = ("--no-update", "--version")
REPLACEMENT = "\u2757"
OUTPUT_LIMIT = 256 << 20
TEMPLATE_DIR = "template"
TMP_DIR = "tmp"
_HOST_KEYS: tuple[tuple[str, str], ...] = (
    ("color.ui", "never"),
    ("color.diff", "never"),
    ("diff.noprefix", "false"),
    ("diff.mnemonicPrefix", "false"),
    ("diff.srcPrefix", "a/"),
    ("diff.dstPrefix", "b/"),
    ("diff.renames", "false"),
    ("log.abbrevCommit", "false"),
    ("log.showRoot", "true"),
)

FILE_LIMIT = 65_536
VALUE_LIMIT = 1 << 20
PARTS_LIMIT = 16
EMAIL_LIMIT = 1024
TIMESTAMP_LIMIT = 64
_LINE_LIMIT = (1 << 63) - 1

_ERROR_LINE = re.compile(rb'\{\s*"level"\s*:\s*"error"')
_LEVEL_HEAD = 256
_DETECTORS: Mapping[SecretType, str] = {
    candidate.kind: candidate.trufflehog for candidate in CANDIDATES
}


class NoDetectorsEnabled(ValueError):
    def __init__(self) -> None:
        super().__init__("every TruffleHog detector is turned off")


def template_config(private: Path) -> tuple[tuple[str, str], ...]:
    never = never_made(private)
    return (
        *(pair for pair in safe_config(str(never / "hooks")) if pair[0] != "core.hooksPath"),
        *_HOST_KEYS,
        ("core.attributesFile", str(never / "no-attributes")),
    )


TEMPLATE_KEYS: tuple[str, ...] = tuple(key for key, _ in template_config(Path("cwd")))


def write_template(
    runner: GitRunner,
    template_dir: Path,
    *,
    timeout: float,
    cancel: threading.Event | None,
) -> None:
    template_dir.mkdir(mode=0o700)
    config = str(template_dir / "config")
    for key, value in template_config(template_dir.parent):
        runner.run(
            ["config", "--file", config, key, value],
            cwd=runner.private_dir,
            timeout=timeout,
            cancel=cancel,
        )


def shadow_uri(shadow: PurePath) -> str:
    uri = shadow.as_uri()
    drive = shadow.drive
    if len(drive) == 2 and drive[1] == ":":
        return "file://" + uri.removeprefix("file:///")
    return uri


def invocation(
    trufflehog: Path, shadow: Path, dirs: RunDirs, options: TruffleHogOptions
) -> list[str]:
    results = "unverified" if options.hide_word_filtered else "unverified,filtered_unverified"
    argv = [
        str(trufflehog),
        "git",
        shadow_uri(shadow),
        "--bare",
        "--no-verification",
        "--no-update",
        "--json",
        "--no-ignore-tag",
        "--fail-on-scan-errors",
        f"--results={results}",
    ]
    if options.filter_entropy:
        argv.append(f"--filter-entropy={options.filter_entropy!r}")
    if options.filter_unverified:
        argv.append("--filter-unverified")
    if options.detectors_off:
        argv.append("--exclude-detectors=" + ",".join(sorted(options.detectors_off)))
    if options.skip_binaries:
        argv.append("--force-skip-binaries")
    if options.skip_archives:
        argv.append("--force-skip-archives")
    argv.append(f"--detector-timeout={options.detector_timeout_seconds}s")
    return argv


GIT_SHIM = "git-shim"


def run_env(dirs: RunDirs) -> ToolEnv:
    tmp = str(dirs.private / TMP_DIR)
    return {
        **tool_env(dirs.private, extra_config=[FILE_CLONE]),
        "GIT_TEMPLATE_DIR": str(dirs.private / TEMPLATE_DIR),
        "TMPDIR": tmp,
        "TMP": tmp,
        "TEMP": tmp,
    }


def git_shim(dirs: RunDirs, path_env: str) -> Path | None:
    if sys.platform == "win32":
        return None
    searched = os.pathsep.join(
        entry for entry in path_env.split(os.pathsep) if entry and os.path.isabs(entry)
    )
    folder = dirs.private / GIT_SHIM
    folder.mkdir(mode=0o700)
    body = (
        "#!/bin/sh\n"
        f"PATH={shlex.quote(searched)}\n"
        f"GIT_TRACE2_EVENT={shlex.quote(str(trace_dir(dirs.private)))}\n"
        "export PATH GIT_TRACE2_EVENT\n"
        'exec git "$@"\n'
    )
    fd = os.open(folder / "git", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "w") as script:
        script.write(body)
    return folder


def canary_keeps(options: TruffleHogOptions) -> Callable[[SecretType], bool]:
    if options.hide_word_filtered or options.filter_entropy > 0:
        return lambda _kind: False
    off = {name.split(".", 1)[0] for name in options.detectors_off}
    return lambda kind: _DETECTORS[kind] not in off


_PartKey = Annotated[str, Strict(), Field(min_length=1), cut_to(RULE_LIMIT)]
_PartValue = Annotated[str, Strict(), within_bytes(VALUE_LIMIT)]
_GIT_KEYS = ("commit", "file", "line", "email", "timestamp")
_RESULT_KEYS = ("DetectorName", "DecoderName", "Raw", "SecretParts", "Verified")


class TruffleHogRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, hide_input_in_errors=True)

    commit: Annotated[str, Strict(), Field(pattern=r"^[0-9a-f]{40}$")]
    file: Annotated[str, Strict(), within_bytes(FILE_LIMIT)] | None = None
    line: Annotated[int, Strict(), Field(ge=0, le=_LINE_LIMIT)] = 0
    email: Annotated[str, Strict(), cut_to(EMAIL_LIMIT)] = ""
    timestamp: Annotated[str, Strict(), cut_to(TIMESTAMP_LIMIT)] = ""
    detector: Annotated[
        str, Strict(), Field(alias="DetectorName", min_length=1), cut_to(RULE_LIMIT)
    ]
    decoder: Annotated[str, Strict(), Field(alias="DecoderName"), cut_to(RULE_LIMIT)] = ""
    raw: Annotated[str, Strict(), Field(alias="Raw", repr=False), within_bytes(VALUE_LIMIT)]
    parts: Annotated[
        dict[_PartKey, _PartValue],
        Strict(),
        Field(alias="SecretParts", repr=False, max_length=PARTS_LIMIT),
    ] = {}
    verified: Annotated[bool, Strict(), Field(alias="Verified")] = False

    @model_validator(mode="before")
    @classmethod
    def _flattened(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        source = data.get("SourceMetadata")
        held = source.get("Data") if isinstance(source, dict) else None
        git = held.get("Git") if isinstance(held, dict) else None
        if not isinstance(git, dict):
            raise ValueError("a result with no git place")
        flat = {key: data[key] for key in _RESULT_KEYS if data.get(key) is not None}
        flat.update({key: git[key] for key in _GIT_KEYS if key in git})
        if flat.get("file") == "":
            del flat["file"]
        return flat


def _other_source(item: Any) -> Uncommitted | Hosted | None:
    if not isinstance(item, dict) or not isinstance(item.get("DetectorName"), str):
        return None
    source = item.get("SourceMetadata")
    held = source.get("Data") if isinstance(source, dict) else None
    if not isinstance(held, dict) or "Git" in held:
        return None
    commits = (place.get("commit") for place in held.values() if isinstance(place, dict))
    return HOSTED if any(isinstance(commit, str) and commit for commit in commits) else UNCOMMITTED


def _items(chunks: Iterable[bytes]) -> Iterator[TruffleHogRecord | Uncommitted | Hosted | None]:
    for item in json_lines(chunks):
        try:
            yield TruffleHogRecord.model_validate(item)
        except ValidationError:
            yield _other_source(item)


def parse_results(chunks: Iterable[bytes]) -> Iterator[TruffleHogRecord | None]:
    for item in _items(chunks):
        yield item if isinstance(item, TruffleHogRecord) else None


def name_and_email(text: str) -> tuple[str, str]:
    at = text.rfind("<")
    if not text.endswith(">") or at == -1 or ">" in text[at + 1 : -1]:
        return "", text
    name = text[:at].rstrip()
    if "\n" in name:
        return "", text
    return name, text[at + 1 : -1]


def _authored(record: TruffleHogRecord) -> ReportedCommit:
    name, email = name_and_email(record.email)
    try:
        at: datetime | None = datetime.strptime(
            record.timestamp, "%Y-%m-%d %H:%M:%S %z"
        ).astimezone(UTC)
    except (ValueError, OverflowError):
        at = None
    return ReportedCommit(
        matched_line=bounded_bytes(record.raw.encode("utf-8"), MATCH_LIMIT),
        author_name=name,
        author_email=email,
        authored_at=at,
    )


def _imported(record: TruffleHogRecord) -> list[Reported]:
    report = _authored(record)
    return [
        replace(found, report=report, reported_live=record.verified)
        for found in reported_values(record)
    ]


def reported_values(record: TruffleHogRecord) -> list[Reported]:
    raw = record.raw.encode("utf-8")
    place = ReportedPlace(record.commit, record.file, record.line)
    found = [Reported(record.detector, place, raw)]
    for key, part in record.parts.items():
        value = part.encode("utf-8")
        held = trimmed_value(value)
        if held and held not in raw:
            found.append(Reported(f"{record.detector}:{key}", replace(place, holding=held), value))
    return found


def logged_error(chunks: Iterable[bytes]) -> bool:
    return any(_ERROR_LINE.match(head) for head in line_heads(chunks, _LEVEL_HEAD))


def _values(chunks: Iterable[bytes]) -> Iterator[Reported | None]:
    for record in parse_results(chunks):
        if record is None:
            yield None
        else:
            yield from reported_values(record)


def _imported_values(reading: Reading) -> Iterator[Reported | None]:
    imported = reading.imported
    if imported is None:
        raise TypeError("the reading is no import's")
    for record in tallied(imported.tally, _items(reading.read("stdout"))):
        if record is None:
            yield None
        else:
            yield from _imported(record)


def read_results(reading: Reading) -> OutputRead:
    def record(held: Sequence[Reported], recorder: Recorder) -> None:
        record_reported(reading, held, recorder, replacement=REPLACEMENT)

    values = (
        _values(reading.read("stdout")) if reading.imported is None else _imported_values(reading)
    )
    read = read_findings(reading, values, record, name="trufflehog")
    if read.dropped:
        reading.progress.add_gaps(CoverageGaps(records_dropped=read.dropped))
    return OutputRead(whole=not read.refused, canary_seen=read.canary_seen, refused=read.refused)


def judge_results(reading: Reading) -> Verdict:
    read = read_results(reading)
    if reading.canary_commit is None:
        canary = CanaryState.NOT_CHECKED
    else:
        canary = CanaryState.SEEN if read.canary_seen else CanaryState.MISSING
    code = reading.exit_code
    if code is not None and code != 0:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.EXIT_CODE, canary, read)
    if code is None:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, canary, read)
    if logged_error(reading.read("stderr")):
        return Verdict(ToolRunState.FAILED, ToolRunFailure.TOOL_REPORTED_ERROR, canary, read)
    if not read.whole:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, canary, read)
    if canary is CanaryState.MISSING:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.INCOMPLETE, canary, read)
    return Verdict(ToolRunState.DONE, None, canary, read)


def _judged(reading: Reading, progress: Progress, checked: ToolRunFailure | None) -> RunOutcome:
    progress.parser_version = PARSER_VERSION
    verdict = judge_results(reading)
    progress.canary = verdict.canary
    return finished(progress, verdict.state, verdict.failure, checked)


def gaps(census: Census | None) -> CoverageGaps:
    return census_gaps(census, long_lines=True, merges=True, type_changes=True)


def _scan(
    ctx: RunContext, dirs: RunDirs, git_dir: Path, options: TruffleHogOptions, progress: Progress
) -> RunOutcome:
    shadow = prepare_shadow(ctx, dirs, git_dir, progress)
    if isinstance(shadow, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, shadow)
    canary = plant_canary(
        ctx.runner,
        shadow,
        keeps=canary_keeps(options),
        timeout=ctx.timeout,
        cancel=ctx.cancel,
    )
    if canary is not None:
        progress.canary_commit = canary.commit
    write_template(ctx.runner, dirs.private / TEMPLATE_DIR, timeout=ctx.timeout, cancel=ctx.cancel)
    (dirs.private / TMP_DIR).mkdir(mode=0o700)
    code: int | ToolRunFailure | None
    checked: ToolRunFailure | None = None
    try:
        with watched_space(dirs.run) as space:
            env = run_env(dirs)
            shim = git_shim(dirs, env["PATH"])
            if shim is not None:
                env["PATH"] = f"{shim}{os.pathsep}{env['PATH']}"
            code = run_tool_process(
                invocation(ctx.tool_file(), shadow, dirs, options),
                cwd=dirs.private,
                env=env,
                stdout=dirs.stdout,
                stderr=dirs.stderr,
                timeout=ctx.timeout,
                cancel=ctx.cancel,
                max_output=OUTPUT_LIMIT,
            )
        checked = ran_whole(dirs, space, progress, needs=None if shim is None else "log")
    except NotStarted:
        code = ToolRunFailure.TOOL_UNAVAILABLE
    except ToolOutputTooLarge:
        code = None
    finally:
        seal_parts(ctx, progress, {"stdout": dirs.stdout, "stderr": dirs.stderr})
    if isinstance(code, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, code)
    progress.exit_code = code
    rechecked = recheck_containment(ctx)
    if rechecked != git_dir:
        failure = rechecked if isinstance(rechecked, ToolRunFailure) else None
        return progress.outcome(ToolRunState.FAILED, failure or ToolRunFailure.OUTSIDE_ROOT)
    progress.add_gaps(gaps(progress.census))
    reading = ctx.reading(
        shadow, exit_code=code, canary_commit=None if canary is None else canary.commit
    )
    try:
        return _judged(reading, progress, checked)
    except (GitCancelled, GitTimeout):
        raise
    except (GitError, SealError):
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNREADABLE)


def _run(ctx: RunContext, progress: Progress) -> RunOutcome:
    options = ctx.options_as(TruffleHogOptions)
    if no_rules(options):
        raise NoDetectorsEnabled
    if ctx.cancel.is_set():
        raise GitCancelled("trufflehog")
    git_dir = recheck_containment(ctx)
    if isinstance(git_dir, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, git_dir)
    ctx.tool_file()
    dirs = make_run_dirs(ctx.work_dir, ctx.run_id)
    try:
        return _scan(ctx, dirs, git_dir, options, progress)
    finally:
        remove_run_dirs(dirs)


@dataclass(frozen=True)
class TruffleHogSpec:
    name: ToolName = ToolName.TRUFFLEHOG
    coverage: str = "history"
    offline: bool = True
    parser_version: int = PARSER_VERSION

    def detect(
        self,
        path_env: str,
        operator_path: Path | None,
        *,
        known_builds: Mapping[str, str],
        exec_path: Path | None,
        git_version: str | None,
        work_dir: Path,
    ) -> Detection:
        return detect_versioned(
            self.name.value,
            VERSION_ARGS,
            VERSION,
            floor=FLOOR,
            tested=TESTED,
            path_env=path_env,
            operator_path=operator_path,
            private=work_dir,
        )

    def run(self, ctx: RunContext) -> RunOutcome:
        progress = ctx.progress
        try:
            return _run(ctx, progress)
        except GitCancelled:
            return progress.outcome(ToolRunState.CANCELLED)
        except GitTimeout:
            return progress.outcome(ToolRunState.TIMED_OUT)
        except ToolChanged as changed:
            return progress.outcome(ToolRunState.FAILED, changed.failure)

    def read_output(self, reading: Reading) -> OutputRead:
        return read_results(reading)

    def judge_output(self, reading: Reading) -> Verdict:
        return judge_results(reading)
