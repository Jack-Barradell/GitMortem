import os
import re
import tempfile
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from gitmortem.crypto import SealError
from gitmortem.db.models import FindingPlace, MetaFrom, ToolName, ToolRunFailure, ToolRunState
from gitmortem.gitread import git_env, unquote_c_style
from gitmortem.gitrun import (
    DEFAULT_TIMEOUT,
    GitCancelled,
    GitError,
    GitRunner,
    GitTimeout,
)
from gitmortem.scanning.carrier import carrier_findings_place
from gitmortem.scanning.metadata import CommitMeta, read_commit_meta
from gitmortem.scanning.objects import missing_objects
from gitmortem.scanning.options import GitSecretsOptions
from gitmortem.scanning.process import watched_space
from gitmortem.scanning.repos import display_path
from gitmortem.scanning.run import (
    Progress,
    Recorder,
    RunDirs,
    census_gaps,
    finished,
    make_run_dirs,
    prepare_shadow,
    ran_whole,
    read_findings,
    remove_run_dirs,
    seal_parts,
)
from gitmortem.scanning.streams import MAX_ITEM_BYTES
from gitmortem.scanning.tools import (
    FINDINGS_BATCH,
    CoverageGaps,
    Detection,
    OutputRead,
    ParsedFinding,
    Reading,
    RunContext,
    RunOutcome,
    ToolChanged,
    Verdict,
    detect_executable,
    is_shadowed,
    recheck_containment,
)
from gitmortem.scanning.trace import trace_dir

KNOWN_BUILDS: dict[str, str] = {
    "df9a5d2beeda1c83e23105f46efe464bb4c97f8328e1e66754d7daacfaf7272b": "1.3.0",
}

PATTERNS: tuple[str, ...] = (
    "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "(\"|')?(AWS|aws|Aws)?_?(SECRET|secret|Secret)?_?(ACCESS|access|Access)?_?(KEY|key|Key)"
    "(\"|')?\\s*(:|=>|=)\\s*(\"|')?[A-Za-z0-9/\\+=]{40}(\"|')?",
    "(\"|')?(AWS|aws|Aws)?_?(ACCOUNT|account|Account)_?(ID|id|Id)?(\"|')?\\s*(:|=>|=)\\s*"
    "(\"|')?[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}(\"|')?",
)

_EXAMPLE_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
ALLOWED_EXAMPLES: tuple[str, ...] = tuple(
    f"(^|[^A-Za-z0-9_]){value}([^A-Za-z0-9_]|$)" for value in (_EXAMPLE_KEY_ID, _EXAMPLE_SECRET)
)

BANNER = (
    b"\n"
    b"[ERROR] Matched one or more prohibited patterns\n"
    b"\n"
    b"Possible mitigations:\n"
    b"- Mark false positives as allowed using: git config --add secrets.allowed ...\n"
    b"- Mark false positives as allowed by adding regular expressions to .gitallowed at "
    b"repository's root directory\n"
    b"- List your configured patterns: git config --get-all secrets.patterns\n"
    b"- List your configured allowed patterns: git config --get-all secrets.allowed\n"
    b"- List your configured allowed patterns in .gitallowed at repository's root directory\n"
    b"- Use --no-verify if this is a one-time false positive\n"
)

UNMATCHED_RULE = "git-secrets:unmatched"
GREP_BATCH = 500
BATCHED_GREP_FILE = "batched-grep.bash"
_BATCHED_GREP = """git() {
  if [ "$1" = grep ] && [ "$2" = -nwHEI ] && [ "$#" -gt @OVER@ ]; then
    local arg
    for arg in "${@:4}"; do
      [[ $arg =~ ^[0-9a-f]{40}$ ]] || { command git "$@"; return; }
    done
    local pattern="$3" status=1 code take
    shift 3
    while [ "$#" -gt 0 ]; do
      take=@BATCH@
      [ "$#" -lt "$take" ] && take=$#
      command git grep -nwHEI "$pattern" "${@:1:take}"
      code=$?
      shift "$take"
      case $code in
        0) status=0 ;;
        1) ;;
        *) return "$code" ;;
      esac
    done
    return "$status"
  fi
  command git "$@"
}
"""
PARSER_VERSION = 1
_TOOL = "git-secrets"
_GLOB = frozenset("*?[")
_TREE_CHECK_BYTES = 4 << 20
_MAX_SPLITS = 64
PATH_LIMIT = 65_536
LINE_LIMIT = MAX_ITEM_BYTES
_TOO_LONG = b"\0too long\0"


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str
    pattern: re.Pattern[bytes]


def _word(body: bytes) -> re.Pattern[bytes]:
    return re.compile(rb"(?<![A-Za-z0-9_])" + body + rb"(?![A-Za-z0-9_])")


_QUOTE = b"(?:\"|')"
_SECRET_CLASS = rb"[A-Za-z0-9/\\+=]"

RULES: tuple[Rule, ...] = (
    Rule(
        "aws-access-key-id",
        "aws-access-key-id",
        _word(rb"(?P<value>(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"),
    ),
    Rule(
        "aws-secret-access-key",
        "aws-secret-access-key",
        _word(
            _QUOTE
            + rb"?(?:AWS|aws|Aws)?_?(?:SECRET|secret|Secret)?_?(?:ACCESS|access|Access)?_?"
            + rb"(?:KEY|key|Key)"
            + _QUOTE
            + rb"?\s*(?::|=>|=)\s*"
            + _QUOTE
            + rb"?(?P<value>"
            + _SECRET_CLASS
            + rb"{40})"
            + _QUOTE
            + rb"?+"
        ),
    ),
    Rule(
        "aws-account-id",
        "aws-account-id",
        _word(
            _QUOTE
            + rb"?(?:AWS|aws|Aws)?_?(?:ACCOUNT|account|Account)_?(?:ID|id|Id)?"
            + _QUOTE
            + rb"?\s*(?::|=>|=)\s*"
            + _QUOTE
            + rb"?(?P<value>[0-9]{4}-?[0-9]{4}-?[0-9]{4})"
            + _QUOTE
            + rb"?+"
        ),
    ),
)


@dataclass(frozen=True)
class Match:
    rule: str
    kind: str
    value: bytes = field(repr=False)


def extract(content: bytes) -> list[Match]:
    found: list[tuple[int, int, int, Rule, bytes]] = []
    for order, rule in enumerate(RULES):
        for match in rule.pattern.finditer(content):
            found.append((match.start("value"), match.end("value"), order, rule, match["value"]))
    found.sort(key=lambda each: (each[0], each[0] - each[1], each[2]))
    kept: list[Match] = []
    reach = -1
    for start, end, _, rule, value in found:
        if start < reach:
            continue
        kept.append(Match(rule.name, rule.kind, value))
        reach = end
    return kept


def write_pattern_file(
    runner: GitRunner,
    path: Path,
    *,
    git_dir: Path,
    allow_aws_examples: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    cancel: threading.Event | None = None,
) -> None:
    if os.path.lexists(path):
        raise FileExistsError("the pattern file already exists")
    entries = [("secrets.patterns", pattern) for pattern in PATTERNS]
    if allow_aws_examples:
        entries += [("secrets.allowed", allowed) for allowed in ALLOWED_EXAMPLES]
    for key, value in entries:
        runner.run(
            ["config", "--file", str(path), "--add", key, value],
            cwd=runner.private_dir,
            extra_env={"GIT_DIR": str(git_dir)},
            timeout=timeout,
            cancel=cancel,
        )


class UnsafeWorkTree(Exception):
    def __init__(self) -> None:
        super().__init__("the empty work tree's path holds whitespace or a glob character")


def _unsafe(path: Path) -> bool:
    return any(char.isspace() or char in _GLOB for char in str(path))


def make_dirs(work_dir: Path, run_id: int) -> RunDirs:
    dirs = make_run_dirs(work_dir, run_id)
    try:
        empty_tree = Path(tempfile.mkdtemp(prefix="gitmortem-tree-")).resolve()
    except BaseException:
        remove_run_dirs(dirs)
        raise
    made = replace(dirs, empty_tree=empty_tree, pattern_file=dirs.run / "patterns.gitconfig")
    if _unsafe(empty_tree):
        remove_run_dirs(made)
        raise UnsafeWorkTree
    return made


def batched_grep(batch: int = GREP_BATCH) -> str:
    if batch < 1:
        raise ValueError("a batch holds at least one commit")
    return _BATCHED_GREP.replace("@OVER@", str(batch + 3)).replace("@BATCH@", str(batch))


def batched_grep_file(dirs: RunDirs) -> Path:
    return dirs.run / BATCHED_GREP_FILE


def write_batched_grep(path: Path, batch: int = GREP_BATCH) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as out:
        out.write(batched_grep(batch).encode("ascii"))


def _own_files(dirs: RunDirs) -> tuple[Path, Path]:
    if dirs.empty_tree is None or dirs.pattern_file is None:
        raise ValueError("git-secrets runs in folders made by make_dirs")
    return dirs.empty_tree, dirs.pattern_file


@dataclass(frozen=True)
class Invocation:
    args: tuple[str, ...]
    extra_env: Mapping[str, str]
    extra_config: tuple[tuple[str, str], ...]
    path_first: tuple[Path, ...]
    cwd: Path


def build_invocation(dirs: RunDirs, shadow: Path, tool_dir: Path) -> Invocation:
    empty_tree, pattern_file = _own_files(dirs)
    return Invocation(
        args=("secrets", "--scan-history"),
        extra_env=MappingProxyType(
            {
                "GIT_DIR": str(shadow),
                "GIT_WORK_TREE": str(empty_tree),
                "GIT_CONFIG": str(pattern_file),
                "GIT_TRACE2_EVENT": str(trace_dir(dirs.private)),
                "BASH_ENV": str(batched_grep_file(dirs)),
            }
        ),
        extra_config=(("core.quotePath", "true"),),
        path_first=(tool_dir,),
        cwd=dirs.private,
    )


@dataclass(frozen=True)
class Hit:
    commit: str
    path: bytes
    line: int
    content: bytes = field(repr=False)
    place: FindingPlace = FindingPlace.LINE


_HEAD = re.compile(rb"[0-9a-f]{40}:")
_NO_COMMIT = re.compile(rb"[^:\n]+:[1-9][0-9]{0,17}:")
_LINE_NUMBER = re.compile(rb":([1-9][0-9]{0,17}):")
_QUOTED_BYTE = re.compile(rb'[\x00-\x1f"\\\x7f-\xff]')


@dataclass(frozen=True)
class _Split:
    commit: str
    rest: bytes = field(repr=False)
    splits: tuple[tuple[int, int, int], ...]

    def name(self, split: tuple[int, int, int]) -> bytes:
        return self.commit.encode("ascii") + b":" + self.rest[: split[0]]

    def hit(self, split: tuple[int, int, int], place: FindingPlace = FindingPlace.LINE) -> Hit:
        end, line, content = split
        return Hit(self.commit, self.rest[:end], line, self.rest[content:], place)

    def unsettled(self) -> Hit:
        if len(self.splits) == 1:
            return self.hit(self.splits[0], FindingPlace.UNRESOLVED)
        return Hit(self.commit, b"", 0, self.rest, FindingPlace.UNRESOLVED)


def _read_line(line: bytes) -> Hit | _Split | None:
    if _HEAD.match(line) is None:
        return None
    commit, rest = line[:40].decode("ascii"), line[41:]
    if rest[:1] == b'"':
        unquoted = unquote_c_style(rest)
        if unquoted is None:
            return None
        path, after = unquoted
        number = _LINE_NUMBER.match(after)
        if not path or number is None:
            return None
        return Hit(commit, path, int(number[1]), after[number.end() :])
    quoted = _QUOTED_BYTE.search(rest)
    limit = len(rest) if quoted is None else quoted.start()
    if rest.startswith((b"./", b"../")):
        return None
    splits: list[tuple[int, int, int]] = []
    at = rest.find(b":", 1)
    while at != -1 and at < min(limit, PATH_LIMIT + 1) and len(splits) < _MAX_SPLITS:
        number = _LINE_NUMBER.match(rest, at)
        if number is not None:
            splits.append((at, int(number[1]), number.end()))
        at = rest.find(b":", at + 1)
    return _Split(commit, rest, tuple(splits)) if splits else None


class TreeCheck(Protocol):
    def blobs(self, names: Sequence[bytes]) -> list[bool]: ...


@dataclass(frozen=True)
class GitTreeCheck:
    runner: GitRunner
    git_dir: Path
    cwd: Path
    timeout: float
    cancel: threading.Event | None = None

    def blobs(self, names: Sequence[bytes]) -> list[bool]:
        out = self.runner.run(
            ["cat-file", "--batch-check=%(objecttype)"],
            cwd=self.cwd,
            stdin=b"".join(name + b"\n" for name in names),
            timeout=self.timeout,
            cancel=self.cancel,
            extra_env=git_env(self.git_dir),
            max_stdout=sum(len(name) for name in names) + len(names) * 16 + 1024,
        )
        answers = out.split(b"\n")
        if len(answers) != len(names) + 1 or answers[-1]:
            raise GitError("cat-file", 0, "git cat-file did not answer each name once")
        return [answer == b"blob" for answer in answers[:-1]]


class _BannerAtEnd:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = chunks
        self.found = False

    def __iter__(self) -> Iterator[bytes]:
        held = b""
        for chunk in self._chunks:
            held += chunk
            if len(held) > len(BANNER):
                cut = len(held) - len(BANNER)
                yield held[:cut]
                held = held[cut:]
        if held == BANNER:
            self.found = True
        else:
            yield held


def _lines(chunks: Iterable[bytes]) -> Iterator[bytes]:
    pending = bytearray()
    over = False
    for chunk in chunks:
        start = 0
        while (end := chunk.find(b"\n", start)) != -1:
            if not over:
                pending += chunk[start:end]
            yield _TOO_LONG if over or len(pending) > LINE_LIMIT else bytes(pending)
            pending.clear()
            over = False
            start = end + 1
        if not over:
            pending += chunk[start:]
            if len(pending) > LINE_LIMIT:
                pending.clear()
                over = True
    if over:
        yield _TOO_LONG
    elif pending:
        yield bytes(pending)


class OutputParser:
    def __init__(self, tree: TreeCheck, *, batch: int = FINDINGS_BATCH) -> None:
        self._tree = tree
        self._batch = batch
        self._imported = False
        self.issues = 0
        self.records = 0
        self.uncommitted = 0
        self.too_long = 0

    @classmethod
    def for_import(cls, tree: TreeCheck, *, batch: int = FINDINGS_BATCH) -> "OutputParser":
        parser = cls(tree, batch=batch)
        parser._imported = True
        return parser

    def parse(self, chunks: Iterable[bytes]) -> Iterator[list[Hit]]:
        body = _BannerAtEnd(chunks)
        read: list[Hit | _Split] = []
        any_line = False
        for line in _lines(body):
            if not line:
                continue
            any_line = True
            if line == _TOO_LONG:
                self.issues += 1
                self.too_long += 1
                continue
            found = _read_line(line)
            if found is None:
                if self._imported and _NO_COMMIT.match(line):
                    self.records += 1
                    self.uncommitted += 1
                else:
                    self.issues += 1
                continue
            self.records += 1
            read.append(found)
            if len(read) == self._batch:
                if hits := self._settle(read):
                    yield hits
                read = []
        if read and (hits := self._settle(read)):
            yield hits
        if self._imported:
            if body.found and not any_line:
                self.issues += 1
        elif not body.found or not any_line:
            self.issues += 1

    def _settle(self, read: Sequence[Hit | _Split]) -> list[Hit]:
        blobs: dict[int, list[int]] = {}
        asking: dict[bytes, list[tuple[int, int]]] = {}
        size = 0

        def ask() -> None:
            names = list(asking)
            for name, is_blob in zip(names, self._tree.blobs(names), strict=True):
                if is_blob:
                    for at, split in asking[name]:
                        blobs.setdefault(at, []).append(split)
            asking.clear()

        for at, item in enumerate(read):
            if isinstance(item, Hit):
                continue
            for index, split in enumerate(item.splits):
                name = item.name(split)
                if name not in asking:
                    size += len(name)
                asking.setdefault(name, []).append((at, index))
                if size > _TREE_CHECK_BYTES:
                    ask()
                    size = 0
        if asking:
            ask()
        hits: list[Hit] = []
        for at, item in enumerate(read):
            if isinstance(item, Hit):
                hits.append(item)
            elif len(settled := blobs.get(at, [])) == 1:
                hits.append(item.hit(item.splits[settled[0]]))
            else:
                self.issues += 1
                hits.append(item.unsettled())
        return hits


def findings_of(hit: Hit, meta: CommitMeta | None) -> list[ParsedFinding]:
    shown = display_path(hit.path)

    def finding(rule: str, kind: str | None, value: bytes | None) -> ParsedFinding:
        return ParsedFinding(
            rule=rule,
            kind=kind,
            commit=hit.commit,
            path=hit.path,
            display_path=shown,
            line=hit.line,
            value=value,
            matched_line=hit.content,
            author_name="" if meta is None else meta.author_name,
            author_email="" if meta is None else meta.author_email,
            authored_at=None if meta is None else meta.authored_at,
            meta_from=MetaFrom.NONE if meta is None else MetaFrom.COMMIT,
            commit_message=None if meta is None else meta.message,
            message_cut=meta is not None and meta.message_cut,
            place=hit.place,
        )

    matches = extract(hit.content)
    if not matches:
        return [finding(UNMATCHED_RULE, None, None)]
    return [finding(match.rule, match.kind, match.value) for match in matches]


def _runnable(ctx: RunContext, dirs: RunDirs, shadow: Path) -> bool:
    tool = ctx.tool_file()
    folder = tool.parent
    if not folder.is_absolute() or os.pathsep in str(folder):
        return False
    named = folder / _TOOL
    try:
        if not (
            named.is_file()
            and os.access(named, os.X_OK)
            and os.path.samestat(os.stat(named), os.stat(tool))
        ):
            return False
    except OSError:
        return False
    try:
        exec_path = ctx.runner.run(
            ["--exec-path"],
            cwd=dirs.private,
            extra_env={"GIT_DIR": str(shadow)},
            timeout=ctx.timeout,
            cancel=ctx.cancel,
        )
    except (GitCancelled, GitTimeout):
        raise
    except GitError:
        return False
    return not is_shadowed(tool, Path(os.fsdecode(exec_path).rstrip("\r\n")), _TOOL)


def read_hits(reading: Reading) -> OutputRead:
    imported = reading.imported
    if reading.exit_code == 0 and imported is None:
        said = any(chunk for part in ("stdout", "stderr") for chunk in reading.read(part))
        return OutputRead(whole=not said)
    git_dir = reading.git_dir_on_disk()
    stray = sum(1 for line in _lines(reading.read("stdout")) if line)
    tree = GitTreeCheck(
        reading.runner, git_dir, reading.runner.private_dir, reading.timeout, reading.cancel
    )
    parser = OutputParser(tree) if imported is None else OutputParser.for_import(tree)

    held = reading.carrier_map()

    def carried(hit: Hit) -> Hit | None:
        if held is None or hit.commit != held.commit:
            return hit
        spot = carrier_findings_place(held, hit.path, hit.line)
        if spot is None:
            reading.progress.parse_issues += 1
            return None
        return Hit(spot.commit, spot.path, spot.line, hit.content, FindingPlace(spot.place))

    def record(hits: Sequence[Hit], recorder: Recorder) -> None:
        hits = [moved for hit in hits if (moved := carried(hit)) is not None]
        metas = read_commit_meta(
            reading.runner,
            git_dir,
            [hit.commit for hit in hits],
            timeout=reading.timeout,
            cancel=reading.cancel,
        )
        unread = [hit.commit for hit in hits if hit.commit not in metas]
        gone = (
            missing_objects(
                reading.runner,
                git_dir,
                unread,
                timeout=reading.timeout,
                cancel=reading.cancel,
            )
            if unread
            else set()
        )
        if imported is not None:
            imported.tally.unknown_commits |= gone
        for hit in hits:
            if hit.place in (FindingPlace.TAG, FindingPlace.OBJECT):
                for finding in findings_of(hit, None):
                    recorder.add(finding)
                continue
            if hit.commit in gone and hit.place is FindingPlace.LINE:
                reading.progress.parse_issues += 1
                if imported is not None:
                    hit = replace(hit, place=FindingPlace.UNRESOLVED)
            for finding in findings_of(hit, metas.get(hit.commit)):
                recorder.add(finding)

    hits = (hit for batch in parser.parse(reading.read("stderr")) for hit in batch)
    try:
        read_findings(reading, hits, record, name="secrets")
    finally:
        reading.progress.parse_issues += stray + parser.issues
        if imported is not None:
            imported.tally.records += parser.records
            imported.tally.uncommitted += parser.uncommitted
            imported.tally.unreadable += stray + parser.issues
    if imported is not None:
        return OutputRead(whole=True)
    if parser.too_long:
        reading.progress.add_gaps(CoverageGaps(records_dropped=parser.too_long))
    return OutputRead(whole=reading.exit_code == 1)


def judge_hits(reading: Reading) -> Verdict:
    if reading.exit_code not in (0, 1):
        return Verdict(ToolRunState.FAILED, ToolRunFailure.EXIT_CODE)
    read = read_hits(reading)
    if not read.whole:
        return Verdict(ToolRunState.FAILED, ToolRunFailure.UNEXPECTED_OUTPUT, read=read)
    return Verdict(ToolRunState.DONE, read=read)


def _scan(
    ctx: RunContext,
    dirs: RunDirs,
    git_dir: Path,
    options: GitSecretsOptions,
    progress: Progress,
) -> RunOutcome:
    shadow = prepare_shadow(ctx, dirs, git_dir, progress)
    if isinstance(shadow, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, shadow)
    if not _runnable(ctx, dirs, shadow):
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.TOOL_UNAVAILABLE)
    _, pattern_file = _own_files(dirs)
    write_pattern_file(
        ctx.runner,
        pattern_file,
        git_dir=shadow,
        allow_aws_examples=options.allow_aws_examples,
        timeout=ctx.timeout,
        cancel=ctx.cancel,
    )
    write_batched_grep(batched_grep_file(dirs), GREP_BATCH)
    invocation = build_invocation(dirs, shadow, ctx.tool_file().parent)
    try:
        with watched_space(dirs.run) as space:
            code = ctx.runner.capture(
                invocation.args,
                cwd=invocation.cwd,
                stdout=dirs.stdout,
                stderr=dirs.stderr,
                timeout=ctx.timeout,
                cancel=ctx.cancel,
                extra_env=invocation.extra_env,
                extra_config=invocation.extra_config,
                path_first=invocation.path_first,
            )
        checked = ran_whole(dirs, space, progress)
    finally:
        seal_parts(ctx, progress, {"stdout": dirs.stdout, "stderr": dirs.stderr})
    progress.exit_code = code
    rechecked = recheck_containment(ctx)
    if rechecked != git_dir:
        failure = rechecked if isinstance(rechecked, ToolRunFailure) else None
        return progress.outcome(ToolRunState.FAILED, failure or ToolRunFailure.OUTSIDE_ROOT)
    progress.parser_version = PARSER_VERSION
    progress.add_gaps(census_gaps(progress.census))
    try:
        verdict = judge_hits(ctx.reading(shadow, exit_code=code))
    except (GitCancelled, GitTimeout):
        raise
    except (GitError, SealError):
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNREADABLE)
    return finished(progress, verdict.state, verdict.failure, checked)


def _run(ctx: RunContext, progress: Progress) -> RunOutcome:
    options = ctx.options_as(GitSecretsOptions)
    if ctx.cancel.is_set():
        raise GitCancelled("secrets")
    git_dir = recheck_containment(ctx)
    if isinstance(git_dir, ToolRunFailure):
        return progress.outcome(ToolRunState.FAILED, git_dir)
    ctx.tool_file()
    try:
        dirs = make_dirs(ctx.work_dir, ctx.run_id)
    except UnsafeWorkTree:
        return progress.outcome(ToolRunState.FAILED, ToolRunFailure.UNSAFE_WORK_TREE)
    try:
        return _scan(ctx, dirs, git_dir, options, progress)
    finally:
        remove_run_dirs(dirs)


@dataclass(frozen=True)
class GitSecretsSpec:
    name: ToolName = ToolName.GIT_SECRETS
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
        return detect_executable(
            self.name.value,
            path_env,
            operator_path,
            known_builds=known_builds,
            exec_path=exec_path,
            git_version=git_version,
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
        return read_hits(reading)

    def judge_output(self, reading: Reading) -> Verdict:
        return judge_hits(reading)
