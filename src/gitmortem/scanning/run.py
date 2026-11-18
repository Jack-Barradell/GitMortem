import os
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Final, Literal, Protocol

from gitmortem.db.models import (
    CanaryState,
    FindingPlace,
    IntegrityState,
    MetaFrom,
    ToolRunFailure,
    ToolRunState,
)
from gitmortem.gitrun import (
    DISCARD,
    GitCancelled,
    GitError,
    GitTimeout,
    ShadowRefused,
    WorktreesUnreadable,
    shadow_git_dir,
)
from gitmortem.scanning.carrier import (
    CARRIER_PART,
    Carried,
    CarrierMap,
    Census,
    carrier_findings_place,
    plant_carrier,
)
from gitmortem.scanning.metadata import CommitMeta, read_commit_meta
from gitmortem.scanning.objects import missing_objects
from gitmortem.scanning.places import ReportedPlace, ResolvedPlace, resolve_places
from gitmortem.scanning.process import SpaceWatch
from gitmortem.scanning.repos import display_path
from gitmortem.scanning.streams import StreamRefused
from gitmortem.scanning.tools import (
    ERROR_NAME_CHARS,
    FINDINGS_BATCH,
    CoverageGaps,
    ImportTally,
    ParsedFinding,
    Reading,
    RecordFindings,
    RunContext,
    RunDiagnosis,
    RunOutcome,
    trimmed_value,
)
from gitmortem.scanning.trace import GitTrace, judge_trace, make_trace_dir, trace_dir
from gitmortem.trees import remove_tree

__all__ = [
    "FSCK",
    "HOSTED",
    "UNCOMMITTED",
    "WALK",
    "Hosted",
    "ItemsRead",
    "Progress",
    "Recorder",
    "Reported",
    "ReportedCommit",
    "RunDirs",
    "Uncommitted",
    "census_gaps",
    "finished",
    "make_run_dirs",
    "prepare_shadow",
    "ran_whole",
    "read_findings",
    "record_reported",
    "remove_run_dirs",
    "seal_parts",
    "step",
    "tallied",
]

WALK = ("rev-list", "--objects", "--all")
FSCK = ("fsck", "--full", "--no-progress")
FSCK_OUTPUT_MAX = 64 << 20
CARRIED_TEXT_MAX = 1 << 20
_DANGLING = re.compile(rb"dangling (commit|tag|tree|blob) ([0-9a-f]{40})")


@dataclass(frozen=True)
class RunDirs:
    run: Path
    private: Path
    empty_tree: Path | None = None
    pattern_file: Path | None = None

    @property
    def shadow(self) -> Path:
        return self.run / "shadow"

    @property
    def stdout(self) -> Path:
        return self.run / "stdout"

    @property
    def stderr(self) -> Path:
        return self.run / "stderr"


def make_run_dirs(work_dir: Path, run_id: int) -> RunDirs:
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        work_dir.chmod(0o700)
    run = work_dir.resolve() / str(run_id)
    run.mkdir(mode=0o700)
    private = run / "cwd"
    try:
        private.mkdir(mode=0o700)
        make_trace_dir(private)
    except BaseException:
        remove_tree(run)
        raise
    return RunDirs(run, private)


def remove_run_dirs(dirs: RunDirs) -> None:
    try:
        remove_tree(dirs.run)
    finally:
        if dirs.empty_tree is not None:
            remove_tree(dirs.empty_tree)


@dataclass
class Progress:
    integrity: IntegrityState = IntegrityState.NOT_CHECKED
    exit_code: int | None = None
    parse_issues: int = 0
    findings_count: int = 0
    raw_parts: list[str] = field(default_factory=list)
    parser_version: int | None = None
    canary: CanaryState | None = None
    canary_commit: str | None = None
    coverage_gaps: CoverageGaps | None = None
    census: Census | None = None
    git_trace: GitTrace | None = None
    error: str | None = None

    def failed_with(self, error: BaseException) -> None:
        self.error = type(error).__name__[:ERROR_NAME_CHARS]

    @property
    def diagnosis(self) -> RunDiagnosis | None:
        if self.git_trace is None and self.error is None:
            return None
        return RunDiagnosis(git=self.git_trace, error=self.error)

    def add_gaps(self, gaps: CoverageGaps) -> None:
        if self.coverage_gaps is None and gaps == CoverageGaps():
            return
        held = self.coverage_gaps or CoverageGaps()
        self.coverage_gaps = CoverageGaps(
            **{
                name: getattr(held, name) + getattr(gaps, name)
                for name in CoverageGaps.model_fields
            }
        )

    def outcome(self, state: ToolRunState, failure: ToolRunFailure | None = None) -> RunOutcome:
        return RunOutcome(
            state=state,
            failure=failure,
            exit_code=self.exit_code,
            integrity=self.integrity,
            parse_issues=self.parse_issues,
            findings_count=self.findings_count,
            raw_parts=tuple(self.raw_parts),
            parser_version=self.parser_version,
            canary=self.canary,
            canary_commit=self.canary_commit,
            coverage_gaps=self.coverage_gaps,
            diagnosis=self.diagnosis,
        )


class Recorder:
    def __init__(self, record: RecordFindings, progress: Progress) -> None:
        self._record = record
        self._progress = progress
        self._held: list[ParsedFinding] = []

    def add(self, finding: ParsedFinding) -> None:
        self._held.append(finding)
        while len(self._held) >= FINDINGS_BATCH:
            self._hand_over(FINDINGS_BATCH)

    def flush(self) -> None:
        while self._held:
            self._hand_over(min(len(self._held), FINDINGS_BATCH))

    def _hand_over(self, size: int) -> None:
        batch = self._held[:size]
        self._record(batch)
        del self._held[:size]
        self._progress.findings_count += size


@dataclass(frozen=True)
class ReportedCommit:
    matched_line: bytes = field(repr=False)
    author_name: str = ""
    author_email: str = ""
    authored_at: datetime | None = None
    message: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Reported:
    rule: str
    place: ReportedPlace
    value: bytes = field(repr=False)
    kind: str | None = None
    report: ReportedCommit | None = None
    reported_live: bool | None = None

    @property
    def commit(self) -> str:
        return self.place.commit


def _in_message(place: ResolvedPlace, value: bytes, meta: CommitMeta | None) -> ResolvedPlace:
    needle = trimmed_value(value)
    message = b"" if meta is None else meta.message.encode("utf-8")
    at = message.find(needle) if needle else -1
    if at == -1:
        return replace(place, line=0, matched_line=None)
    start = message.rfind(b"\n", 0, at) + 1
    end = message.find(b"\n", at)
    return replace(
        place,
        line=message.count(b"\n", 0, at) + 1,
        matched_line=message[start : len(message) if end == -1 else end],
    )


def _parsed(
    item: Reported,
    place: ResolvedPlace,
    *,
    author: tuple[str, str, datetime | None],
    message: str | None,
    message_cut: bool,
    meta_from: MetaFrom,
) -> ParsedFinding:
    standalone = item.value in (b"", b"\n", b"\r\n")
    kind = item.rule if item.kind is None else item.kind
    name, email, at = author
    return ParsedFinding(
        rule=item.rule,
        kind=None if standalone else kind,
        commit=item.place.commit,
        path=place.path,
        display_path=place.display_path,
        line=place.line,
        value=None if standalone else item.value,
        matched_line=place.matched_line or b"",
        author_name=name,
        author_email=email,
        authored_at=at,
        meta_from=meta_from,
        commit_message=message,
        message_cut=message_cut,
        place=place.place,
        reported_live=item.reported_live,
    )


def _finding(item: Reported, place: ResolvedPlace, meta: CommitMeta | None) -> ParsedFinding:
    if meta is None:
        return _parsed(
            item,
            place,
            author=("", "", None),
            message=None,
            message_cut=False,
            meta_from=MetaFrom.NONE,
        )
    return _parsed(
        item,
        place,
        author=(meta.author_name, meta.author_email, meta.authored_at),
        message=meta.message,
        message_cut=meta.message_cut,
        meta_from=MetaFrom.COMMIT,
    )


def _as_reported(item: Reported, place: FindingPlace) -> ParsedFinding:
    report = item.report
    if report is None:
        raise TypeError("only an imported report's value is built from its report")
    reported = item.place.reported_path
    path = b"" if reported is None else reported.encode("utf-8", "replace")
    at = ResolvedPlace(
        place, path, display_path(path) if path else "", item.place.line, report.matched_line
    )
    return _parsed(
        item,
        at,
        author=(report.author_name, report.author_email, report.authored_at),
        message=report.message,
        message_cut=False,
        meta_from=MetaFrom.REPORT,
    )


def _line_of(text: bytes, value: bytes) -> tuple[int, bytes | None]:
    needle = trimmed_value(value)
    at = text.find(needle) if needle else -1
    if at == -1:
        return 0, None
    start = text.rfind(b"\n", 0, at) + 1
    end = text.find(b"\n", at)
    return text.count(b"\n", 0, at) + 1, text[start : len(text) if end == -1 else end]


def _object_text(reading: Reading, kind: str, spec: bytes) -> bytes:
    try:
        return reading.runner.run(
            ["cat-file", "--end-of-options", kind, spec],
            cwd=reading.runner.private_dir,
            extra_env={"GIT_DIR": str(reading.git_dir_on_disk())},
            timeout=reading.timeout,
            cancel=reading.cancel,
            max_stdout=CARRIED_TEXT_MAX,
        )
    except (GitCancelled, GitTimeout):
        raise
    except GitError:
        return b""


def _carried_place(reading: Reading, item: Reported, spot: Carried) -> tuple[ResolvedPlace, bool]:
    place = FindingPlace(spot.place)
    shown = display_path(spot.path) if spot.path else ""
    if place is FindingPlace.MESSAGE:
        return ResolvedPlace(place, b"", "", 0, None), True
    if place is FindingPlace.NAME:
        return ResolvedPlace(place, spot.path, shown, 0, spot.path[:CARRIED_TEXT_MAX]), True
    if place is FindingPlace.TAG:
        body = _object_text(reading, "tag", spot.commit.encode())
        at = body.find(b"\n\n")
        line, matched = _line_of(body[at + 2 :] if at != -1 else b"", item.value)
        return ResolvedPlace(place, b"", "", line, matched), False
    path = item.place.exact_path or (item.place.reported_path or "").encode("utf-8")
    blob = path.split(b"/")[1]
    if place is FindingPlace.OBJECT:
        spec = spot.commit.encode() + (b":" + spot.path if spot.path else b"")
        line, matched = _line_of(_object_text(reading, "blob", spec), item.value)
        return ResolvedPlace(place, spot.path, shown, line or spot.line, matched), False
    line, matched = _line_of(_object_text(reading, "blob", blob), item.value)
    return ResolvedPlace(FindingPlace.LINE, spot.path, shown, line or spot.line, matched), True


def _record_carried(
    reading: Reading, items: Sequence[Reported], held: CarrierMap, recorder: Recorder
) -> None:
    placed: list[tuple[Reported, ResolvedPlace, bool]] = []
    for item in items:
        path = item.place.exact_path or (item.place.reported_path or "").encode("utf-8")
        spot = carrier_findings_place(held, path, item.place.line)
        if spot is None:
            reading.progress.parse_issues += 1
            continue
        moved = replace(item, place=replace(item.place, commit=spot.commit))
        resolved, of_commit = _carried_place(reading, moved, spot)
        placed.append((moved, resolved, of_commit))
    commits = list(dict.fromkeys(item.place.commit for item, _, of_commit in placed if of_commit))
    metas = read_commit_meta(
        reading.runner,
        reading.git_dir_on_disk(),
        commits,
        timeout=reading.timeout,
        cancel=reading.cancel,
    )
    for item, resolved, of_commit in placed:
        meta = metas.get(item.place.commit) if of_commit else None
        if resolved.place is FindingPlace.MESSAGE:
            resolved = _in_message(resolved, item.value, meta)
        recorder.add(_finding(item, resolved, meta))


def record_reported(
    reading: Reading,
    reported: Sequence[Reported],
    recorder: Recorder,
    *,
    replacement: str,
) -> None:
    held = reading.carrier_map() if reading.git_dir is not None else None
    if held is not None and any(item.place.commit == held.commit for item in reported):
        _record_carried(
            reading, [item for item in reported if item.place.commit == held.commit], held, recorder
        )
        reported = [item for item in reported if item.place.commit != held.commit]
        if not reported:
            return
    if reading.git_dir is None:
        for item in reported:
            where = FindingPlace.MESSAGE if item.place.reported_path is None else FindingPlace.LINE
            recorder.add(_as_reported(item, where))
        return
    places = resolve_places(
        reading.runner,
        reading.git_dir,
        [item.place for item in reported],
        replacement=replacement,
        timeout=reading.timeout,
        cancel=reading.cancel,
        cache=reading.blobs,
    )
    commits = list(dict.fromkeys(item.place.commit for item in reported))
    metas = read_commit_meta(
        reading.runner,
        reading.git_dir,
        commits,
        timeout=reading.timeout,
        cancel=reading.cancel,
    )
    lacking: set[str] = set()
    if reading.imported is not None:
        unread = [commit for commit in commits if commit not in metas]
        if unread:
            lacking = missing_objects(
                reading.runner,
                reading.git_dir,
                unread,
                timeout=reading.timeout,
                cancel=reading.cancel,
            )
        reading.imported.tally.unknown_commits |= lacking
    for item, place in zip(reported, places, strict=True):
        if item.place.commit in lacking and item.report is not None:
            reading.progress.parse_issues += 1
            recorder.add(_as_reported(item, FindingPlace.UNRESOLVED))
            continue
        meta = metas.get(item.place.commit)
        if place.place is FindingPlace.MESSAGE:
            place = _in_message(place, item.value, meta)
        if place.place is FindingPlace.UNRESOLVED:
            reading.progress.parse_issues += 1
        recorder.add(_finding(item, place, meta))


class Placed(Protocol):
    @property
    def commit(self) -> str: ...


class _Mark(Enum):
    UNCOMMITTED = "uncommitted"
    HOSTED = "hosted"


UNCOMMITTED: Final = _Mark.UNCOMMITTED
HOSTED: Final = _Mark.HOSTED
type Uncommitted = Literal[_Mark.UNCOMMITTED]
type Hosted = Literal[_Mark.HOSTED]


def tallied[T](
    tally: ImportTally, items: Iterable[T | Uncommitted | Hosted | None]
) -> Iterator[T | None]:
    try:
        for item in items:
            if item is None:
                tally.unreadable += 1
                yield None
            elif item is UNCOMMITTED:
                tally.records += 1
                tally.uncommitted += 1
            elif item is HOSTED:
                tally.records += 1
                tally.hosted += 1
            else:
                tally.records += 1
                yield item
    except StreamRefused as refused:
        tally.refusal = refused.reason
        raise


@dataclass
class ItemsRead:
    items: int = 0
    canary_seen: bool = False
    refused: bool = False
    dropped: int = 0


CANCEL_EVERY = 1000


def read_findings[T: Placed](
    reading: Reading,
    items: Iterable[T | None],
    record: Callable[[Sequence[T], Recorder], None],
    *,
    name: str,
) -> ItemsRead:
    read = ItemsRead()
    recorder = Recorder(reading.record, reading.progress)
    held: list[T] = []
    try:
        try:
            for item in items:
                read.items += 1
                if read.items % CANCEL_EVERY == 0 and reading.cancel.is_set():
                    raise GitCancelled(name, command=name)
                if item is None:
                    reading.progress.parse_issues += 1
                    read.dropped += 1
                elif reading.canary_commit is not None and item.commit == reading.canary_commit:
                    read.canary_seen = True
                else:
                    held.append(item)
                if len(held) >= FINDINGS_BATCH:
                    if reading.cancel.is_set():
                        raise GitCancelled(name, command=name)
                    record(held, recorder)
                    held.clear()
        except StreamRefused:
            reading.progress.parse_issues += 1
            read.refused = True
        if held:
            record(held, recorder)
    except Exception:
        recorder.flush()
        raise
    recorder.flush()
    return read


def step(ctx: RunContext, args: Sequence[str], shadow: Path, private: Path) -> int:
    return ctx.runner.capture(
        args,
        cwd=private,
        stdout=DISCARD,
        stderr=DISCARD,
        timeout=ctx.timeout,
        cancel=ctx.cancel,
        extra_env={"GIT_DIR": str(shadow)},
    )


def prepare_shadow(
    ctx: RunContext, dirs: RunDirs, git_dir: Path, progress: Progress
) -> Path | ToolRunFailure:
    try:
        also = tuple(v.resolve() for v in ctx.versions if v.resolve() != git_dir)
        shadow = shadow_git_dir(
            ctx.runner, git_dir, dirs.shadow, also=also, timeout=ctx.timeout, cancel=ctx.cancel
        )
    except ShadowRefused:
        return ToolRunFailure.SHADOW_REFUSED
    except (GitCancelled, GitTimeout):
        raise
    except (GitError, WorktreesUnreadable):
        return ToolRunFailure.UNREADABLE
    if step(ctx, WALK, shadow, dirs.private) != 0:
        return ToolRunFailure.UNREADABLE
    listed = dirs.run / "fsck"
    try:
        fsck = ctx.runner.capture(
            FSCK,
            cwd=dirs.private,
            stdout=listed,
            stderr=DISCARD,
            timeout=ctx.timeout,
            cancel=ctx.cancel,
            extra_env={"GIT_DIR": str(shadow)},
        )
        progress.integrity = IntegrityState.VERIFIED if fsck == 0 else IntegrityState.FAILED
    except GitTimeout:
        progress.integrity = IntegrityState.TIMED_OUT
    try:
        census, held = plant_carrier(
            ctx.runner,
            shadow,
            dangling=_dangling(listed),
            timeout=ctx.timeout,
            cancel=ctx.cancel,
        )
    except (GitCancelled, GitTimeout):
        raise
    except GitError:
        return ToolRunFailure.UNREADABLE
    finally:
        listed.unlink(missing_ok=True)
    progress.census = census
    if held is not None:
        ctx.raw_store.write_bytes(ctx.scan_id, ctx.run_id, CARRIER_PART, held.dumps())
        progress.raw_parts.append(CARRIER_PART)
    return shadow


def ran_whole(
    dirs: RunDirs, space: SpaceWatch, progress: Progress, *, needs: str | None = None
) -> ToolRunFailure | None:
    verdict = judge_trace(trace_dir(dirs.private))
    progress.git_trace = verdict.summary(needed=needs)
    if space.low:
        return ToolRunFailure.NO_SPACE
    if not verdict.finished or (needs is not None and needs not in verdict.ended):
        return ToolRunFailure.GIT_INTERRUPTED
    return None


def census_gaps(
    census: Census | None,
    *,
    binary: bool = True,
    long_lines: bool = False,
    too_large: int = 0,
    merges: bool = False,
    type_changes: bool = False,
) -> CoverageGaps:
    if census is None:
        return CoverageGaps()
    return CoverageGaps(
        archives=census.archives,
        encoded_text=census.encoded_text,
        lfs_pointers=census.lfs_pointers,
        binary=census.binary if binary else 0,
        long_lines=census.long_lines if long_lines else 0,
        too_large=too_large,
        merges_not_read=census.merges_with_changes if merges else 0,
        type_changes=census.type_changes if type_changes else 0,
        not_carried=census.not_carried,
    )


def finished(
    progress: Progress,
    state: ToolRunState,
    failure: ToolRunFailure | None,
    checked: ToolRunFailure | None,
) -> RunOutcome:
    if state is ToolRunState.DONE and checked is not None:
        return progress.outcome(ToolRunState.FAILED, checked)
    return progress.outcome(state, failure)


def _dangling(listed: Path) -> list[tuple[str, str]]:
    try:
        with listed.open("rb") as held:
            data = held.read(FSCK_OUTPUT_MAX)
    except OSError:
        return []
    return [
        (match[2].decode("ascii"), match[1].decode("ascii")) for match in _DANGLING.finditer(data)
    ]


def seal_parts(ctx: RunContext, progress: Progress, parts: Mapping[str, Path]) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for part in sorted(parts):
        path = parts[part]
        if not path.exists():
            continue
        sizes[part] = path.stat().st_size
        ctx.raw_store.write(ctx.scan_id, ctx.run_id, part, path)
        progress.raw_parts.append(part)
        path.unlink()
    return sizes
