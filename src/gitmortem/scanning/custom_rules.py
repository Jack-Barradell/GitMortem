import base64
import binascii
import json
import os
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from gitmortem import __version__
from gitmortem.crypto import SealError
from gitmortem.db.models import ToolName, ToolRunFailure, ToolRunState
from gitmortem.gitread import MATCH_LIMIT
from gitmortem.gitrun import DISCARD, GitCancelled, GitError, GitTimeout
from gitmortem.scanning.options import CustomRulesRun
from gitmortem.scanning.places import ReportedPlace
from gitmortem.scanning.process import run_tool_process, tool_env
from gitmortem.scanning.rule_patterns import RuleRefusal, StoredRule, compile_rule
from gitmortem.scanning.rules import MAX_NAME_CHARS
from gitmortem.scanning.rules_walk import (
    CHILD_TIMED_OUT,
    CHILD_UNREADABLE,
    CHILD_WALKED,
    HEADER_LIMIT,
    MAX_MERGE_HELD_BYTES,
    REPLACEMENT,
    go_text,
)
from gitmortem.scanning.run import (
    Progress,
    Recorder,
    Reported,
    RunDirs,
    census_gaps,
    make_run_dirs,
    prepare_shadow,
    read_findings,
    record_reported,
    remove_run_dirs,
    seal_parts,
)
from gitmortem.scanning.streams import json_lines
from gitmortem.scanning.tools import (
    CoverageGaps,
    Detection,
    DetectionStatus,
    OutputRead,
    Reading,
    RunContext,
    RunOutcome,
    Verdict,
    recheck_containment,
)

__all__ = [
    "HITS",
    "PARSER_VERSION",
    "CustomRulesSpec",
    "HitsRead",
    "child_argv",
    "judge_hits",
    "parse_hits",
    "read_hits",
    "record_hits",
]

PARSER_VERSION = 1
CHILD_GRACE_SECONDS = 30.0
HITS = "hits"
_NAME = "custom rules"
_RECORD_LIMIT = 4 << 20
_LINE_LIMIT = (1 << 63) - 1


class HitRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    commit: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{40}$")]
    path: Annotated[StrictStr, Field(min_length=1, max_length=2 * HEADER_LIMIT)]
    line: Annotated[StrictInt, Field(ge=1, le=_LINE_LIMIT)]
    rule: Annotated[StrictInt, Field(ge=1)]
    kind: Annotated[StrictStr, Field(min_length=1, max_length=MAX_NAME_CHARS)]
    spans: Annotated[
        list[Annotated[list[StrictInt], Field(min_length=4, max_length=4)]], Field(min_length=1)
    ]
    text: Annotated[StrictStr, Field(repr=False, max_length=2 * MATCH_LIMIT)]


class SummaryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gaps: CoverageGaps


def _unb64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _reported(record: HitRecord) -> list[Reported] | None:
    path, line = _unb64(record.path), _unb64(record.text)
    if not path or line is None or len(line) > MATCH_LIMIT:
        return None
    text = go_text(line)
    found = []
    for start, end, value_start, value_end in record.spans:
        if not 0 <= start <= value_start < value_end <= end <= len(text):
            return None
        found.append(
            Reported(
                rule=f"custom:{record.rule}",
                place=ReportedPlace(
                    record.commit, path.decode("utf-8", "replace"), record.line, exact_path=path
                ),
                value=text[value_start:value_end].encode("utf-8"),
                kind=record.kind,
            )
        )
    return found


def parse_hits(chunks: Iterable[bytes]) -> Iterator[Reported | CoverageGaps | None]:
    for item in json_lines(chunks, max_line_bytes=_RECORD_LIMIT):
        if isinstance(item, dict) and "gaps" in item:
            try:
                yield SummaryRecord.model_validate(item).gaps
            except ValidationError:
                yield None
            continue
        try:
            record = HitRecord.model_validate(item)
        except ValidationError:
            yield None
            continue
        found = _reported(record)
        if found is None:
            yield None
        else:
            yield from found


@dataclass
class HitsRead:
    gaps: CoverageGaps | None = None
    refused: bool = False

    @property
    def whole(self) -> bool:
        return self.gaps is not None and not self.refused


def _values(
    items: Iterable[Reported | CoverageGaps | None], read: HitsRead
) -> Iterator[Reported | None]:
    for item in items:
        if isinstance(item, CoverageGaps):
            if read.gaps is not None:
                yield None
            read.gaps = item
            continue
        if item is not None and read.gaps is not None:
            yield None
        yield item


def record_hits(reading: Reading, chunks: Iterable[bytes]) -> HitsRead:
    read = HitsRead()

    def record(held: Sequence[Reported], recorder: Recorder) -> None:
        record_reported(reading, held, recorder, replacement=REPLACEMENT)

    items = read_findings(reading, _values(parse_hits(chunks), read), record, name=_NAME)
    read.refused = items.refused
    if read.gaps is None:
        reading.progress.parse_issues += 1
    return read


def read_hits(reading: Reading) -> OutputRead:
    read = record_hits(reading, reading.read(HITS))
    return OutputRead(whole=read.whole, coverage_gaps=read.gaps, refused=read.refused)


def judge_hits(reading: Reading) -> Verdict:
    read = read_hits(reading)
    if not read.whole:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, read=read)
    return Verdict(ToolRunState.DONE, read=read)


def _usable_rules(ctx: RunContext, options: CustomRulesRun) -> tuple[list[StoredRule], int]:
    if ctx.rules is None:
        raise TypeError("a custom-rules run is handed its rules")
    usable: list[StoredRule] = []
    left_out = 0
    for rule in ctx.rules(options.rules):
        if isinstance(compile_rule(rule.pattern), RuleRefusal):
            left_out += 1
        else:
            usable.append(rule)
    return usable, left_out


def child_argv(
    shadow: Path, hits: Path, private: Path, timeout: float, merge_held_bytes: int, left_out: int
) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "gitmortem.scanning.rules_child",
        "--shadow",
        os.fspath(shadow),
        "--hits",
        os.fspath(hits),
        "--private",
        os.fspath(private),
        "--timeout",
        repr(float(timeout)),
        "--merge-held-bytes",
        str(merge_held_bytes),
        "--left-out",
        str(left_out),
    ]


class _ChildFailed(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"the rules child exited {code}")
        self.code = code


def _write_hits(
    ctx: RunContext,
    dirs: RunDirs,
    shadow: Path,
    hits: Path,
    usable: Sequence[StoredRule],
    left_out: int,
    merge_held_bytes: int,
) -> None:
    payload = json.dumps(
        {"rules": [{"id": rule.id, "name": rule.name, "pattern": rule.pattern} for rule in usable]}
    ).encode()
    code = run_tool_process(
        child_argv(shadow, hits, dirs.run / "child-git", ctx.timeout, merge_held_bytes, left_out),
        cwd=dirs.private,
        env=tool_env(dirs.private),
        stdout=DISCARD,
        stderr=DISCARD,
        timeout=ctx.timeout + CHILD_GRACE_SECONDS,
        cancel=ctx.cancel,
        stdin_bytes=payload,
    )
    if code == CHILD_TIMED_OUT:
        raise GitTimeout("rules", ctx.timeout, command=_NAME)
    if code == CHILD_UNREADABLE:
        raise GitError("rules", code)
    if code != CHILD_WALKED:
        raise _ChildFailed(code)


def _scan(
    ctx: RunContext,
    dirs: RunDirs,
    git_dir: Path,
    usable: Sequence[StoredRule],
    left_out: int,
    progress: Progress,
    merge_held_bytes: int,
) -> RunOutcome:
    shadow = prepare_shadow(ctx, dirs, git_dir, progress)
    if isinstance(shadow, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, shadow)
    hits = dirs.run / HITS
    try:
        try:
            _write_hits(ctx, dirs, shadow, hits, usable, left_out, merge_held_bytes)
        finally:
            seal_parts(ctx, progress, {HITS: hits})
    except (GitCancelled, GitTimeout):
        raise
    except GitError:
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNREADABLE)
    except _ChildFailed:
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_ERROR)
    rechecked = recheck_containment(ctx)
    if rechecked != git_dir:
        failure = rechecked if isinstance(rechecked, ToolRunFailure) else None
        return progress.outcome(ToolRunState.FAILED, failure or ToolRunFailure.OUTSIDE_ROOT)
    progress.parser_version = PARSER_VERSION
    try:
        verdict = judge_hits(ctx.reading(shadow))
    except (GitCancelled, GitTimeout):
        raise
    except (GitError, SealError):
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNREADABLE)
    if verdict.read is not None and verdict.read.coverage_gaps is not None:
        progress.coverage_gaps = verdict.read.coverage_gaps
    progress.add_gaps(census_gaps(progress.census, binary=False))
    return progress.outcome(verdict.state, verdict.failure)


def _run(ctx: RunContext, progress: Progress, merge_held_bytes: int) -> RunOutcome:
    options = ctx.options_as(CustomRulesRun)
    if ctx.cancel.is_set():
        raise GitCancelled("rules", command=_NAME)
    usable, left_out = _usable_rules(ctx, options)
    if not usable:
        progress.coverage_gaps = CoverageGaps(rules_left_out=left_out)
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.NO_RULES_ENABLED)
    git_dir = recheck_containment(ctx)
    if isinstance(git_dir, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, git_dir)
    dirs = make_run_dirs(ctx.work_dir, ctx.run_id)
    try:
        return _scan(ctx, dirs, git_dir, usable, left_out, progress, merge_held_bytes)
    finally:
        remove_run_dirs(dirs)


@dataclass(frozen=True)
class CustomRulesSpec:
    name: ToolName = ToolName.CUSTOM_RULES
    coverage: str = "history"
    offline: bool = True
    parser_version: int = PARSER_VERSION
    merge_held_bytes: int = MAX_MERGE_HELD_BYTES

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
        return Detection(DetectionStatus.FOUND, identity=f"{self.name.value} {__version__}")

    def run(self, ctx: RunContext) -> RunOutcome:
        progress = ctx.progress
        try:
            return _run(ctx, progress, self.merge_held_bytes)
        except GitCancelled:
            return progress.outcome(ToolRunState.CANCELLED)
        except GitTimeout:
            return progress.outcome(ToolRunState.TIMED_OUT)

    def read_output(self, reading: Reading) -> OutputRead:
        return read_hits(reading)

    def judge_output(self, reading: Reading) -> Verdict:
        return judge_hits(reading)
