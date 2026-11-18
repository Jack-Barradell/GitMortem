import os
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, Strict, ValidationError

from gitmortem.corpus.fakes import SecretType
from gitmortem.crypto import SealError
from gitmortem.db.models import (
    CanaryState,
    ToolName,
    ToolRunFailure,
    ToolRunState,
)
from gitmortem.gitread import MATCH_LIMIT
from gitmortem.gitrun import GitCancelled, GitError, GitTimeout, NotStarted
from gitmortem.scanning.canary import CANDIDATES, plant_canary
from gitmortem.scanning.carrier import Census
from gitmortem.scanning.gitleaks_config import build_config
from gitmortem.scanning.options import GitleaksOptions
from gitmortem.scanning.places import ReportedPlace
from gitmortem.scanning.process import (
    ToolOutputTooLarge,
    run_tool_process,
    tool_env,
    watched_space,
)
from gitmortem.scanning.run import (
    UNCOMMITTED,
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
from gitmortem.scanning.streams import cut_to, json_array_items, line_heads, within_bytes
from gitmortem.scanning.tools import (
    AUTHOR_LIMIT,
    MESSAGE_LIMIT,
    RULE_LIMIT,
    CoverageGaps,
    Detection,
    ImportTally,
    OutputRead,
    Reading,
    RunContext,
    RunOutcome,
    ToolChanged,
    Verdict,
    bounded_bytes,
    detect_versioned,
    recheck_containment,
)

__all__ = [
    "FOUND",
    "PARSER_VERSION",
    "GitleaksRecord",
    "GitleaksSpec",
    "LoggedErrors",
    "canary_keeps",
    "invocation",
    "judge_report",
    "logged_error",
    "parse_report",
    "read_log",
    "read_report",
]

PARSER_VERSION = 3
FOUND = 10
FLOOR = (8, 25, 0)
TESTED = (8, 30, 1)
VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
VERSION_ARGS = ("version",)
REPLACEMENT = "\ufffd"
LOG_LIMIT = 64 << 20
CONFIG_FILE = "gitleaks.toml"
IGNORE_FILE = "gitleaksignore"
REPORT_FILE = "report.json"
REPORT = "report"
_LOG_OPTS = ("--all", "--full-history", "--diff-filter=uxdb", "--no-textconv", "--no-ext-diff")
_MERGES = "--diff-merges=first-parent"

FILE_LIMIT = 65_536
VALUE_LIMIT = 1 << 20
_LINE_LIMIT = (1 << 63) - 1
_DATE_LIMIT = 64
_MESSAGE_HELD = MESSAGE_LIMIT + 4
_REDACTED = "REDACTED"
_REDACTED_TAIL = "..."

_COLOUR = re.compile(rb"\x1b\[[0-9;]*m")
_ERROR_LEVEL = re.compile(rb"(?:\S+ )?(?:ERR|FTL|PNC)(?: |$)")
_ARCHIVE_UNOPENED = re.compile(
    rb'(?:\S+ )?ERR (?:error="could not read file: '
    rb"|could read compressed file(?: |$)"
    rb"|could not open archive inner file(?: |$))"
)
_LEVEL_HEAD = 256
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
_RULES: Mapping[SecretType, str] = {candidate.kind: candidate.gitleaks for candidate in CANDIDATES}


def invocation(gitleaks: Path, shadow: Path, dirs: RunDirs, options: GitleaksOptions) -> list[str]:
    private = dirs.private
    argv = [
        str(gitleaks),
        "git",
        str(shadow),
        "--config",
        str(private / CONFIG_FILE),
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path",
        str(private / IGNORE_FILE),
        "--report-format",
        "json",
        "--report-path",
        str(private / REPORT_FILE),
        "--no-banner",
        "--no-color",
        "--platform=none",
        "--exit-code",
        str(FOUND),
        "--max-decode-depth",
        str(options.max_decode_depth),
        "--max-archive-depth",
        str(options.max_archive_depth),
    ]
    if options.max_target_megabytes:
        argv += ["--max-target-megabytes", str(options.max_target_megabytes)]
    log_opts = [*_LOG_OPTS, _MERGES] if options.scan_merges else list(_LOG_OPTS)
    argv.append("--log-opts=" + " ".join(log_opts))
    return argv


def canary_keeps(options: GitleaksOptions) -> Callable[[SecretType], bool]:
    return lambda kind: _RULES[kind] not in options.rules_off


def _write_private(path: Path, data: bytes) -> None:
    with os.fdopen(os.open(path, _NEW_FILE, 0o600), "wb") as out:
        out.write(data)


class GitleaksRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, hide_input_in_errors=True)

    rule_id: Annotated[str, Strict(), Field(alias="RuleID", min_length=1), cut_to(RULE_LIMIT)]
    file: Annotated[str, Strict(), Field(alias="File"), cut_to(FILE_LIMIT)]
    secret: Annotated[str, Strict(), Field(alias="Secret", repr=False), within_bytes(VALUE_LIMIT)]
    match: Annotated[str, Strict(), Field(alias="Match", repr=False), within_bytes(VALUE_LIMIT)]
    commit: Annotated[str, Strict(), Field(alias="Commit", pattern=r"^[0-9a-f]{40}$")]
    start_line: Annotated[int, Strict(), Field(alias="StartLine", ge=0, le=_LINE_LIMIT)]
    author: Annotated[str, Strict(), Field(alias="Author"), cut_to(AUTHOR_LIMIT)] = ""
    email: Annotated[str, Strict(), Field(alias="Email"), cut_to(AUTHOR_LIMIT)] = ""
    date: Annotated[str, Strict(), Field(alias="Date"), cut_to(_DATE_LIMIT)] = ""
    message: Annotated[str, Strict(), Field(alias="Message", repr=False), cut_to(_MESSAGE_HELD)] = (
        ""
    )


def _without_commit(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    rule = item.get("RuleID")
    return isinstance(rule, str) and bool(rule) and item.get("Commit") in ("", None)


def _items(chunks: Iterable[bytes]) -> Iterator[GitleaksRecord | Uncommitted | None]:
    for item in json_array_items(chunks):
        try:
            yield GitleaksRecord.model_validate(item)
        except ValidationError:
            yield UNCOMMITTED if _without_commit(item) else None


def parse_report(chunks: Iterable[bytes]) -> Iterator[GitleaksRecord | None]:
    for item in _items(chunks):
        yield item if isinstance(item, GitleaksRecord) else None


@dataclass(frozen=True)
class LoggedErrors:
    unopened_archives: int
    other: bool


def read_log(chunks: Iterable[bytes]) -> LoggedErrors:
    unopened = 0
    other = False
    for head in line_heads(chunks, _LEVEL_HEAD):
        line = _COLOUR.sub(b"", head)
        if not _ERROR_LEVEL.match(line):
            continue
        if _ARCHIVE_UNOPENED.match(line):
            unopened += 1
        else:
            other = True
    return LoggedErrors(unopened, other)


def logged_error(chunks: Iterable[bytes]) -> bool:
    return read_log(chunks).other


def _reported(record: GitleaksRecord) -> Reported:
    return Reported(
        record.rule_id,
        ReportedPlace(record.commit, record.file, record.start_line),
        record.secret.encode("utf-8"),
    )


def _date(text: str) -> datetime | None:
    try:
        at = datetime.fromisoformat(text)
        return None if at.tzinfo is None else at.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _redacted(record: GitleaksRecord) -> bool:
    secret = record.secret
    return secret == _REDACTED or (secret.endswith(_REDACTED_TAIL) and secret in record.match)


def _imported(record: GitleaksRecord, tally: ImportTally) -> Reported:
    reported = _reported(record)
    value = reported.value
    if _redacted(record):
        tally.redacted += 1
        value = b""
    return Reported(
        reported.rule,
        reported.place,
        value,
        report=ReportedCommit(
            matched_line=bounded_bytes(record.match.encode("utf-8"), MATCH_LIMIT),
            author_name=record.author,
            author_email=record.email,
            authored_at=_date(record.date),
            message=record.message,
        ),
    )


def read_report(reading: Reading) -> OutputRead:
    if REPORT not in reading.parts:
        return OutputRead(whole=False)

    def record(held: Sequence[Reported], recorder: Recorder) -> None:
        record_reported(reading, held, recorder, replacement=REPLACEMENT)

    if reading.imported is not None:
        tally = reading.imported.tally
        read = read_findings(
            reading,
            (
                None if item is None else _imported(item, tally)
                for item in tallied(tally, _items(reading.read(REPORT)))
            ),
            record,
            name="gitleaks",
        )
        return OutputRead(whole=not read.refused, refused=read.refused)
    read = read_findings(
        reading,
        (None if item is None else _reported(item) for item in parse_report(reading.read(REPORT))),
        record,
        name="gitleaks",
    )
    if read.dropped:
        reading.progress.add_gaps(CoverageGaps(records_dropped=read.dropped))
    agrees = reading.exit_code in (0, FOUND) and (reading.exit_code == FOUND) == (read.items > 0)
    return OutputRead(
        whole=agrees and not read.refused, canary_seen=read.canary_seen, refused=read.refused
    )


def judge_report(reading: Reading) -> Verdict:
    planted = reading.canary_commit is not None
    if reading.exit_code not in (0, FOUND):
        return Verdict(ToolRunState.FAILED, ToolRunFailure.EXIT_CODE)
    if REPORT not in reading.parts:
        canary = CanaryState.MISSING if planted else CanaryState.NOT_CHECKED
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, canary)
    read = read_report(reading)
    canary = _canary(planted, read)
    logged = read_log(reading.read("stderr"))
    if logged.unopened_archives:
        unopened = CoverageGaps(archives_unopened=logged.unopened_archives)
        reading.progress.add_gaps(unopened)
        read = replace(read, coverage_gaps=unopened)
    if logged.other:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.TOOL_REPORTED_ERROR, canary, read)
    if not read.whole:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, canary, read)
    if canary is CanaryState.MISSING:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.INCOMPLETE, canary, read)
    return Verdict(ToolRunState.DONE, None, canary, read)


def _canary(planted: bool, read: OutputRead) -> CanaryState:
    if not planted:
        return CanaryState.NOT_CHECKED
    return CanaryState.SEEN if read.canary_seen else CanaryState.MISSING


def _judged(reading: Reading, progress: Progress, checked: ToolRunFailure | None) -> RunOutcome:
    progress.parser_version = PARSER_VERSION
    if reading.canary_commit is None:
        progress.canary = CanaryState.NOT_CHECKED
    verdict = judge_report(reading)
    progress.canary = verdict.canary
    return finished(progress, verdict.state, verdict.failure, checked)


def gaps(options: GitleaksOptions, census: Census | None) -> CoverageGaps:
    too_large = 0
    if census is not None:
        too_large = (
            census.over(options.max_target_megabytes)
            if options.max_target_megabytes
            else census.big_files
        )
    return census_gaps(census, too_large=too_large, merges=not options.scan_merges)


def _scan(
    ctx: RunContext,
    dirs: RunDirs,
    git_dir: Path,
    options: GitleaksOptions,
    config: bytes,
    progress: Progress,
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
    _write_private(dirs.private / CONFIG_FILE, config)
    _write_private(dirs.private / IGNORE_FILE, b"")
    report = dirs.private / REPORT_FILE
    code: int | ToolRunFailure
    checked: ToolRunFailure | None = None
    try:
        with watched_space(dirs.run) as space:
            code = run_tool_process(
                invocation(ctx.tool_file(), shadow, dirs, options),
                cwd=dirs.private,
                env=tool_env(dirs.private),
                stdout=dirs.stdout,
                stderr=dirs.stderr,
                timeout=ctx.timeout,
                cancel=ctx.cancel,
                max_output=LOG_LIMIT,
            )
        checked = ran_whole(dirs, space, progress)
    except NotStarted:
        code = ToolRunFailure.TOOL_UNAVAILABLE
    except ToolOutputTooLarge:
        code = ToolRunFailure.UNEXPECTED_OUTPUT
    finally:
        seal_parts(ctx, progress, {REPORT: report, "stdout": dirs.stdout, "stderr": dirs.stderr})
    if isinstance(code, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, code)
    progress.exit_code = code
    rechecked = recheck_containment(ctx)
    if rechecked != git_dir:
        failure = rechecked if isinstance(rechecked, ToolRunFailure) else None
        return progress.outcome(ToolRunState.FAILED, failure or ToolRunFailure.OUTSIDE_ROOT)
    progress.add_gaps(gaps(options, progress.census))
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
    options = ctx.options_as(GitleaksOptions)
    config = build_config(options)
    if ctx.cancel.is_set():
        raise GitCancelled("gitleaks")
    git_dir = recheck_containment(ctx)
    if isinstance(git_dir, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, git_dir)
    ctx.tool_file()
    dirs = make_run_dirs(ctx.work_dir, ctx.run_id)
    try:
        return _scan(ctx, dirs, git_dir, options, config, progress)
    finally:
        remove_run_dirs(dirs)


@dataclass(frozen=True)
class GitleaksSpec:
    name: ToolName = ToolName.GITLEAKS
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
        return read_report(reading)

    def judge_output(self, reading: Reading) -> Verdict:
        return judge_report(reading)
