import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import PurePosixPath

from gitmortem.corpus.contexts import (
    Context,
    RenderedFile,
    comment_values,
    filler_file,
    render_file,
)
from gitmortem.corpus.expectations import expected_tools
from gitmortem.corpus.fakes import (
    BaitKind,
    FakeSecret,
    Role,
    SecretType,
    make_aws_pair,
    make_bait,
    make_secret,
)
from gitmortem.corpus.history import (
    CommitSpec,
    FileChange,
    LinkedWorktree,
    Person,
    ReflogEntry,
    RepoHistory,
    TagSpec,
)
from gitmortem.corpus.manifest import (
    HISTORY_SILENCERS,
    Occurrence,
    Placement,
    RepoEntry,
    RepoKind,
    SecretEntry,
    Silencer,
    Size,
)
from gitmortem.corpus.rng import Rng

EPOCH_BASE = 1609750800
DAY = 86400
MAIN = "main"

PEOPLE = (
    Person("Ada Example", "ada@example.com"),
    Person("Grace Sample", "grace@example.org"),
    Person("Alan Demo", "alan@example.com"),
    Person("Edsger Test", "edsger@example.org"),
    Person("Barbara Fixture", "barbara@example.com"),
    Person("Dennis Stub", "dennis@example.org"),
    Person("Margaret Mock", "margaret@example.com"),
    Person("Ken Placeholder", "ken@example.org"),
)

_FILLER_PATHS = {
    "python": ("src", ".py"),
    "javascript": ("web", ".js"),
    "yaml": ("deploy", ".yml"),
    "markdown": ("docs", ".md"),
    "json": ("data", ".json"),
    "text": ("notes", ".txt"),
    "dockerfile": ("docker", ".Dockerfile"),
}
_FILLER_KINDS = tuple(_FILLER_PATHS)
_WORDS = (
    "orders",
    "inventory",
    "billing",
    "reports",
    "gateway",
    "scheduler",
    "importer",
    "exporter",
    "metrics",
    "mailer",
    "search",
    "uploads",
    "audit",
    "queue",
    "pricing",
    "catalog",
    "shipping",
    "ledger",
    "alerts",
    "backups",
)
_EDIT_MESSAGES = (
    "Update the {word} settings",
    "Tidy the {word} notes",
    "Refactor {word}",
    "Fix a typo in {word}",
    "Bump the {word} defaults",
    "Document {word}",
)
_PNG_HEAD = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
_GITIGNORE = b"__pycache__/\n*.log\nnode_modules/\n.venv/\n"
_BLOCK_CONTEXTS = (Context.PEM, Context.MARKDOWN)
_HIDDEN = (Placement.REFLOG_ONLY, Placement.WORKTREE_REF)
_RESET_AFTER = 300


@dataclass(frozen=True)
class Want:
    kind: SecretType | BaitKind
    handle: str | None = None


@dataclass(frozen=True)
class FileSpec:
    path: str | None
    context: Context
    wants: tuple[Want, ...]
    placement: Placement = Placement.HEAD
    silenced_by: tuple[Silencer, ...] = ()
    comment: str | None = None


@dataclass(frozen=True)
class RepoSpec:
    rel: str
    kind: RepoKind = RepoKind.NORMAL
    files: tuple[FileSpec, ...] = ()
    commits: int = 8
    team: int = 2
    start_day: int = 0
    span_days: int = 720
    merges: int = 0
    side_branch: str | None = None
    releases: int = 0
    snapshots: int = 0
    rename: bool = False
    binary: bool = False
    big_files: int = 0
    ignored: tuple[str, ...] = ()
    initial_files: tuple[FileChange, ...] = ()
    plants_last: bool = False


class Values:
    def __init__(self, rng: Rng) -> None:
        self._rng = rng
        self._made: dict[str, tuple[SecretType | BaitKind, tuple[FakeSecret, ...]]] = {}
        self._pairs: dict[str, str] = {}

    def get(self, want: Want, local: str) -> tuple[FakeSecret, ...]:
        if want.kind in (SecretType.AWS_SECRET_ACCESS_KEY, BaitKind.AWS_EXAMPLE_SECRET):
            raise ValueError("an AWS secret is planted with its key id: want the key id instead")
        handle = want.handle if want.handle is not None else local
        if handle in self._made:
            kind, made = self._made[handle]
            if kind is not want.kind:
                raise ValueError(f"handle {handle} is a {kind}, not a {want.kind}")
            return made
        rng = self._rng.derive(handle)
        if want.kind in (SecretType.AWS_ACCESS_KEY_ID, BaitKind.AWS_EXAMPLE):
            if want.kind is SecretType.AWS_ACCESS_KEY_ID:
                key_id, secret = make_aws_pair(rng)
            else:
                key_id = make_bait(BaitKind.AWS_EXAMPLE, rng)
                secret = make_bait(BaitKind.AWS_EXAMPLE_SECRET, rng)
            self._pairs[key_id.value] = secret.value
            self._pairs[secret.value] = key_id.value
            made = (key_id, secret)
        elif isinstance(want.kind, SecretType):
            made = (make_secret(want.kind, rng),)
        else:
            made = (make_bait(want.kind, rng),)
        self._made[handle] = (want.kind, made)
        return made

    def pair_of(self, value: str) -> str | None:
        return self._pairs.get(value)


@dataclass
class _Planted:
    spec: FileSpec
    path: str
    secrets: tuple[FakeSecret, ...]
    rendered: RenderedFile
    branch: str
    mode: int
    introduced: int = 0
    removed: int | None = None


@dataclass(frozen=True)
class _Draft:
    mark: int
    branch: str
    author: Person
    message: str
    parents: tuple[int, ...]
    changes: tuple[FileChange, ...]


def _raw(path: str) -> bytes:
    return path.encode("utf-8", "surrogateescape")


def _text(path: bytes) -> str:
    return path.decode("utf-8", "surrogateescape")


def _display(path: str) -> str:
    return _raw(path).decode("utf-8", "replace")


def _modify(path: str, content: bytes, mode: int = 0o100644) -> FileChange:
    return FileChange("modify", _raw(path), content, mode)


class _Builder:
    def __init__(self, decide: Rng, text: Rng, team: Sequence[Person], reserved: Sequence[str]):
        self.decide = decide
        self.text = text
        self.team = team
        self.drafts: list[_Draft] = []
        self.tips: dict[str, int] = {}
        self.latest: dict[str, bytes] = {}
        self.filler: dict[str, dict[str, str]] = {MAIN: {}}
        self.forks: dict[str, int] = {}
        self.used: dict[str, None] = dict.fromkeys(reserved)
        self.tags: list[tuple[str, int, bool]] = []

    def commit(
        self, branch: str, message: str, changes: Sequence[FileChange], merge: int | None = None
    ) -> int:
        mark = len(self.drafts) + 1
        parents: tuple[int, ...] = (self.tips[branch],) if branch in self.tips else ()
        if merge is not None:
            parents += (merge,)
        author = self.decide.choice(self.team)
        self.drafts.append(_Draft(mark, branch, author, message + "\n", parents, tuple(changes)))
        self.tips[branch] = mark
        return mark

    def fork(self, branch: str) -> None:
        self.tips[branch] = self.forks[branch] = self.tips[MAIN]
        self.filler[branch] = {}

    def fresh_path(self, folder: str, stem: str, suffix: str) -> str:
        path = f"{folder}/{stem}{suffix}"
        n = 2
        while path in self.used:
            path = f"{folder}/{stem}-{n}{suffix}"
            n += 1
        self.used[path] = None
        return path

    def write_filler(self, path: str, kind: str) -> FileChange:
        self.latest[path] = filler_file(kind, self.text)
        return _modify(path, self.latest[path])

    def add_filler(self, branch: str) -> FileChange:
        kind = self.decide.choice(_FILLER_KINDS)
        folder, suffix = _FILLER_PATHS[kind]
        path = self.fresh_path(folder, self.decide.choice(_WORDS), suffix)
        self.filler[branch][path] = kind
        return self.write_filler(path, kind)

    def filler_commit(self, branch: str) -> None:
        files = self.filler[branch]
        if len(files) < 3 or self.decide.below(4) == 0:
            change = self.add_filler(branch)
            message = f"Add {change.path.decode()}"
        else:
            path = self.decide.choice(sorted(files))
            change = self.write_filler(path, files[path])
            word = PurePosixPath(path).stem
            message = self.decide.choice(_EDIT_MESSAGES).format(word=word)
        self.commit(branch, message, [change])

    def plant(self, planted: _Planted) -> None:
        change = _modify(planted.path, planted.rendered.content, planted.mode)
        message = f"Add {_display(planted.path)}"
        planted.introduced = self.commit(planted.branch, message, [change])

    def remove_values(self, planted: _Planted) -> None:
        drop = {n for _, first, last in planted.rendered.spans for n in range(first, last + 1)}
        lines = planted.rendered.content.split(b"\n")
        kept = b"\n".join(line for n, line in enumerate(lines, 1) if n not in drop)
        change = _modify(planted.path, kept, planted.mode)
        message = f"Move the credentials out of {_display(planted.path)}"
        planted.removed = self.commit(planted.branch, message, [change])

    def delete(self, planted: _Planted) -> None:
        change = FileChange("delete", _raw(planted.path))
        message = f"Remove {_display(planted.path)}"
        planted.removed = self.commit(planted.branch, message, [change])

    def hidden(self, planted: _Planted) -> None:
        self.fork(planted.branch)
        self.plant(planted)

    def side_branch(self, name: str, planted: Sequence[_Planted]) -> None:
        self.fork(name)
        self.filler_commit(name)
        for each in planted:
            self.plant(each)
        if self.decide.below(2):
            self.filler_commit(name)

    def feature(self, name: str) -> None:
        self.fork(name)
        for _ in range(self.decide.between(1, 3)):
            self.filler_commit(name)

    def merge(self, name: str) -> None:
        if self.tips[MAIN] == self.forks[name]:
            self.filler_commit(MAIN)
        own = self.filler[name]
        changes = [_modify(path, self.latest[path]) for path in own]
        self.filler[MAIN].update(own)
        self.commit(MAIN, f"Merge branch '{name}'", changes, merge=self.tips[name])

    def rename(self) -> None:
        files = self.filler[MAIN]
        old = self.decide.choice(sorted(files))
        kind = files.pop(old)
        folder, suffix = _FILLER_PATHS[kind]
        new = self.fresh_path(folder, self.decide.choice(_WORDS), suffix)
        files[new] = kind
        self.latest[new] = self.latest.pop(old)
        change = FileChange("rename", old.encode(), new_path=new.encode())
        self.commit(MAIN, f"Rename {old} to {new}", [change])

    def binary(self) -> None:
        path = self.fresh_path("assets", self.decide.choice(_WORDS), ".png")
        content = _PNG_HEAD + self.text.randbytes(self.decide.between(256, 2048))
        self.commit(MAIN, f"Add {path}", [_modify(path, content)])

    def big_file(self) -> None:
        word = self.decide.choice(_WORDS)
        path = self.fresh_path("docs", f"{word}-handbook", ".md")
        size = self.decide.between(200_000, 400_000)
        chunks: list[bytes] = []
        written = 0
        while written < size:
            chunks.append(filler_file("markdown", self.text))
            written += len(chunks[-1])
        self.commit(MAIN, f"Add the {word} handbook", [_modify(path, b"\n".join(chunks))])

    def tag(self, annotated: bool) -> None:
        n = sum(1 for _, _, kind in self.tags if kind == annotated)
        name = f"v1.{n}.0" if annotated else f"build-{n + 1}"
        self.tags.append((name, self.tips[MAIN], annotated))

    def finish(self, start: int, span: int) -> RepoHistory:
        step = span // max(len(self.drafts) - 1, 1)
        jitter = max(step // 3, 1)
        whens = [start + n * step + self.decide.below(jitter) for n in range(len(self.drafts))]
        commits = [
            CommitSpec(
                d.mark, d.branch, d.author, whens[d.mark - 1], d.message, d.parents, d.changes
            )
            for d in self.drafts
        ]
        tags = []
        for name, mark, annotated in self.tags:
            when = whens[mark - 1] + self.decide.between(600, 7200)
            if annotated:
                tagger = self.decide.choice(self.team)
                tags.append(TagSpec(name, mark, True, tagger, when, f"Release {name}\n"))
            else:
                tags.append(TagSpec(name, mark, False, None, when, ""))
        return RepoHistory(commits, tags)


@dataclass(frozen=True)
class PlannedRepo:
    spec: RepoSpec
    history: RepoHistory
    planted: tuple[_Planted, ...]
    tips: dict[str, int]

    @property
    def path(self) -> str:
        root = "outside" if self.spec.kind is RepoKind.OUTSIDE else "repos"
        return f"{root}/{self.spec.rel}"

    @property
    def bare(self) -> bool:
        return self.spec.kind is RepoKind.BARE

    def paths(self) -> list[str]:
        found = []
        for commit in self.history.commits:
            for change in commit.changes:
                found.append(_text(change.path))
                if change.new_path is not None:
                    found.append(_text(change.new_path))
        return found


def _team(rng: Rng, size: int) -> tuple[Person, ...]:
    pool = list(PEOPLE)
    return tuple(pool.pop(rng.below(len(pool))) for _ in range(size))


def _resolve(
    spec: RepoSpec, index: int, file: FileSpec, values: Values, rng: Rng, side: str
) -> _Planted:
    secrets: list[FakeSecret] = []
    for n, want in enumerate(file.wants):
        secrets += values.get(want, f"{spec.rel}#{index}.{n}")
    path = file.path if file.path is not None else dict(secrets[0].parts)["path"]
    if len({secret.value for secret in secrets}) != len(secrets):
        raise ValueError(f"{spec.rel}:{path}: a file plants each value once")
    by_a_tool = any(silencer not in HISTORY_SILENCERS for silencer in file.silenced_by)
    if (file.placement is Placement.SILENCED) != by_a_tool:
        raise ValueError(
            f"{spec.rel}:{path}: a silenced file, and only one, names a tool's silencers"
        )
    in_history = any(silencer in HISTORY_SILENCERS for silencer in file.silenced_by)
    if in_history and file.placement in (Placement.HEAD, Placement.SILENCED):
        raise ValueError(f"{spec.rel}:{path}: a value hidden in history cannot stay at HEAD")
    if file.placement is Placement.HISTORY_ONLY and file.context in _BLOCK_CONTEXTS:
        raise ValueError(
            f"{spec.rel}:{path}: history only needs a file of lines, not {file.context}"
        )
    branch = MAIN
    if file.placement is Placement.SIDE_BRANCH:
        branch = side
    elif file.placement in _HIDDEN:
        branch = f"gitmortem-hidden-{index}"
    mode = 0o100755 if path.endswith(".sh") else 0o100644
    rendered = render_file(file.context, secrets, rng)
    if file.comment is not None:
        rendered = comment_values(rendered, file.context, file.comment)
    return _Planted(file, path, tuple(secrets), rendered, branch, mode)


def plan_repo(spec: RepoSpec, values: Values, rng: Rng) -> PlannedRepo:
    decide = rng.derive("plan")
    side = spec.side_branch or f"wip/{decide.choice(_WORDS)}"
    planted = [
        _resolve(spec, index, file, values, rng.derive(f"file/{index}"), side)
        for index, file in enumerate(spec.files)
    ]
    given = [_text(change.path) for change in spec.initial_files]
    paths: dict[str, None] = {}
    for path in [*given, *(each.path for each in planted)]:
        if path in paths:
            raise ValueError(f"{spec.rel}:{_display(path)} is planted twice")
        paths[path] = None
    builder = _Builder(decide, rng.derive("text"), _team(decide, spec.team), list(paths))

    actions: list[Callable[[], None]] = [
        partial(builder.filler_commit, MAIN) for _ in range(spec.commits)
    ]

    def insert(action: Callable[[], None], after: Callable[[], None] | None = None) -> None:
        low = 0 if after is None else actions.index(after) + 1
        actions.insert(decide.between(low, len(actions)), action)

    last: list[Callable[[], None]] = []
    for each in planted:
        if each.branch != MAIN:
            continue
        plant = partial(builder.plant, each)
        removal: Callable[[], None] | None = None
        if each.spec.placement is Placement.HISTORY_ONLY:
            removal = partial(builder.remove_values, each)
        elif each.spec.placement is Placement.DELETED_FILE:
            removal = partial(builder.delete, each)
        if spec.plants_last:
            last += [plant] if removal is None else [plant, removal]
            continue
        insert(plant)
        if removal is not None:
            insert(removal, after=plant)
    on_side = [each for each in planted if each.spec.placement is Placement.SIDE_BRANCH]
    hidden = [each for each in planted if each.spec.placement in _HIDDEN]
    if sum(each.spec.placement is Placement.WORKTREE_REF for each in hidden) > 1:
        raise ValueError(f"{spec.rel} plants more than one worktree-ref value")
    if on_side:
        insert(partial(builder.side_branch, side, on_side))
    taken = {side}
    for _ in range(spec.merges):
        name = f"feature/{decide.choice(_WORDS)}"
        while name in taken:
            name += "-2"
        taken.add(name)
        start = partial(builder.feature, name)
        insert(start)
        insert(partial(builder.merge, name), after=start)
    for wanted, step in (
        (spec.rename, builder.rename),
        (spec.binary, builder.binary),
    ):
        if wanted:
            insert(step)
    for _ in range(spec.big_files):
        insert(builder.big_file)
    for _ in range(spec.releases):
        insert(partial(builder.tag, True))
    for _ in range(spec.snapshots):
        insert(partial(builder.tag, False))
    actions += last
    actions += [partial(builder.hidden, each) for each in hidden]

    initial = [_modify(".gitignore", _GITIGNORE + "".join(f"{i}\n" for i in spec.ignored).encode())]
    builder.used[".gitignore"] = None
    initial += spec.initial_files
    if "README.md" not in builder.used:
        builder.used["README.md"] = None
        builder.filler[MAIN]["README.md"] = "markdown"
        initial.append(builder.write_filler("README.md", "markdown"))
    initial += [builder.add_filler(MAIN) for _ in range(2)]
    builder.commit(MAIN, "Initial commit", initial)
    for action in actions:
        action()

    start_time = EPOCH_BASE + spec.start_day * DAY + decide.below(DAY // 2)
    history = _kept_aside(spec, builder.finish(start_time, spec.span_days * DAY), hidden)
    tips = {branch: tip for branch, tip in builder.tips.items() if branch not in history.dropped}
    return PlannedRepo(spec, history, tuple(planted), dict(sorted(tips.items())))


def _kept_aside(spec: RepoSpec, history: RepoHistory, hidden: Sequence[_Planted]) -> RepoHistory:
    commits = {commit.mark: commit for commit in history.commits}
    moves: list[ReflogEntry] = []
    worktrees: list[LinkedWorktree] = []
    for each in hidden:
        commit = commits[each.introduced]
        (base,) = commit.parents
        if each.spec.placement is Placement.REFLOG_ONLY:
            subject = commit.message.splitlines()[0]
            moves += [
                ReflogEntry(base, commit.mark, commit.author, commit.when, f"commit: {subject}"),
                ReflogEntry(
                    commit.mark,
                    base,
                    commit.author,
                    commit.when + _RESET_AFTER,
                    "reset: moving to HEAD~1",
                ),
            ]
        else:
            folder = f"{PurePosixPath(spec.rel).name.removesuffix('.git')}-bisect"
            worktrees.append(LinkedWorktree(folder, base, {"refs/bisect/bad": commit.mark}))
    return replace(
        history,
        dropped=tuple(each.branch for each in hidden),
        reflogs={MAIN: tuple(moves)} if moves else {},
        worktrees=tuple(worktrees),
    )


def check_layout(repos: Sequence[PlannedRepo]) -> None:
    seen: set[str] = set()
    for repo in repos:
        if repo.spec.rel in seen:
            raise ValueError(f"repo {repo.spec.rel} is planned twice")
        seen.add(repo.spec.rel)
    for repo in repos:
        rel = PurePosixPath(repo.spec.rel)
        outers = [
            other
            for other in repos
            if other is not repo and rel.is_relative_to(PurePosixPath(other.spec.rel))
        ]
        if repo.spec.kind is not RepoKind.NESTED:
            if outers:
                raise ValueError(
                    f"repo {rel} sits inside {outers[0].spec.rel} but is not marked nested"
                )
            continue
        work_trees = [other for other in outers if not other.bare]
        if not work_trees:
            raise ValueError(f"nested repo {rel} sits inside no other repo's work tree")
        for outer in work_trees:
            inner = str(rel.relative_to(PurePosixPath(outer.spec.rel)))
            if any(path == inner or path.startswith(inner + "/") for path in outer.paths()):
                raise ValueError(f"{outer.spec.rel} tracks files of its nested repo {rel}")
    for repo in repos:
        for worktree in repo.history.worktrees:
            folder = PurePosixPath(repo.spec.rel).parent / worktree.folder
            for other in repos:
                at = PurePosixPath(other.spec.rel)
                if folder == at or folder in at.parents or at in folder.parents:
                    raise ValueError(f"the worktree {folder} of {repo.spec.rel} overlaps {at}")


def _ancestors(parents: Mapping[int, tuple[int, ...]], tip: int) -> set[int]:
    seen: set[int] = set()
    stack = [tip]
    while stack:
        mark = stack.pop()
        if mark not in seen:
            seen.add(mark)
            stack.extend(parents[mark])
    return seen


def realise(
    planned: PlannedRepo, marks: Mapping[int, str]
) -> tuple[RepoEntry, list[tuple[FakeSecret, Occurrence]]]:
    spec = planned.spec
    rel = PurePosixPath(spec.rel)
    parents = {commit.mark: commit.parents for commit in planned.history.commits}
    reach = {branch: _ancestors(parents, tip) for branch, tip in planned.tips.items()}
    entry = RepoEntry(
        id=spec.rel,
        path=planned.path,
        org=str(rel.parent) if len(rel.parts) > 1 else None,
        name=rel.name.removesuffix(".git") if planned.bare else rel.name,
        kind=spec.kind,
        branches={branch: marks[tip] for branch, tip in planned.tips.items()},
        tags={
            tag.name: marks[tag.target]
            for tag in sorted(planned.history.tags, key=lambda tag: tag.name)
        },
        commit_count=len(planned.history.commits),
        hostile=None,
    )
    found = []
    for each in planned.planted:
        by_value = {secret.value: secret for secret in each.secrets}
        removed = marks[each.removed] if each.removed is not None else None
        shown = _display(each.path)
        path_b64 = None if shown == each.path else base64.b64encode(_raw(each.path)).decode()
        for value, line, end_line in each.rendered.spans:
            secret = by_value[value]
            occurrence = Occurrence(
                repo=spec.rel,
                path=shown,
                path_b64=path_b64,
                line=line,
                end_line=end_line,
                introduced=marks[each.introduced],
                removed=removed,
                branches=sorted(
                    branch for branch, seen in reach.items() if each.introduced in seen
                ),
                at_head=each.spec.placement in (Placement.HEAD, Placement.SILENCED),
                placement=each.spec.placement,
                context=each.spec.context.value,
                detected_by=sorted(
                    expected_tools(secret.kind, each.spec.context, each.spec.placement)
                ),
                silenced_by=list(each.spec.silenced_by),
            )
            found.append((secret, occurrence))
    return entry, found


_KIND_ORDER = {kind: n for n, kind in enumerate([*SecretType, *BaitKind])}


def secret_entries(
    found: Sequence[tuple[FakeSecret, Occurrence]], values: Values
) -> list[SecretEntry]:
    grouped: dict[str, tuple[FakeSecret, list[Occurrence]]] = {}
    for secret, occurrence in found:
        grouped.setdefault(secret.value, (secret, []))[1].append(occurrence)
    numbers: dict[str, int] = {}
    counts: dict[SecretType | BaitKind, int] = {}
    for value, (secret, _) in grouped.items():
        counts[secret.kind] = numbers[value] = counts.get(secret.kind, 0) + 1
    ids = {value: f"{secret.kind}-{numbers[value]}" for value, (secret, _) in grouped.items()}
    entries = []
    for value, (secret, occurrences) in grouped.items():
        pair = values.pair_of(value)
        entry = SecretEntry(
            id=ids[value],
            kind=secret.kind.value,
            role=secret.role,
            value=value,
            parts=dict(secret.parts),
            pair=ids[pair] if pair is not None else None,
            occurrences=sorted(occurrences, key=lambda o: (o.repo, o.path, o.line)),
        )
        rank = (secret.role is not Role.PLANTED, _KIND_ORDER[secret.kind], numbers[value])
        entries.append((rank, entry))
    return [entry for _, entry in sorted(entries, key=lambda pair: pair[0])]


@dataclass(frozen=True)
class CorpusPlan:
    repos: tuple[PlannedRepo, ...]
    loose_files: tuple[tuple[str, bytes], ...]
    non_repo_paths: tuple[str, ...]
    values: Values = field(repr=False)


def plan_corpus(seed: int, size: Size) -> CorpusPlan:
    root = Rng.from_seed(seed)
    values = Values(root.derive("corpus values"))
    specs = _core(_SCALE[size])
    if size is not Size.SMALL:
        specs += _extras(root.derive("corpus layout"), size)
    repos = tuple(plan_repo(spec, values, root.derive(spec.rel)) for spec in specs)
    check_layout(repos)
    loose = root.derive("corpus loose")
    loose_files = (
        ("repos/acme/README.txt", filler_file("text", loose)),
        ("repos/handover/notes.md", filler_file("markdown", loose)),
        ("repos/handover/2023/summary.txt", filler_file("text", loose)),
    )
    return CorpusPlan(repos, loose_files, ("repos/acme/README.txt", "repos/handover"), values)


_SCALE = {Size.SMALL: 1, Size.DEMO: 3, Size.LARGE: 3}


def _core(scale: int) -> list[RepoSpec]:
    ci_token = Want(SecretType.GITHUB_PAT, "shared/ci-token")
    payments_db = Want(SecretType.POSTGRES_URL, "acme/payments/db")
    aws_pair = Want(SecretType.AWS_ACCESS_KEY_ID)
    return [
        RepoSpec(
            "inventory-service",
            team=3,
            commits=10 * scale,
            span_days=1300,
            merges=1,
            releases=2,
            snapshots=1,
            rename=True,
            binary=True,
            files=(
                FileSpec(".github/workflows/ci.yml", Context.YAML, (ci_token,)),
                FileSpec(".env", Context.ENV, (aws_pair,), Placement.HISTORY_ONLY),
                FileSpec(".env.example", Context.ENV, (Want(BaitKind.PLACEHOLDER),)),
                FileSpec("package-lock.json", Context.JSON, (Want(BaitKind.LOCKFILE_INTEGRITY),)),
            ),
        ),
        RepoSpec(
            "acme/payments",
            team=3,
            commits=8 * scale,
            start_day=40,
            span_days=1000,
            merges=1,
            releases=1,
            side_branch="feature/sso",
            files=(
                FileSpec(
                    "app/settings.py",
                    Context.PYTHON,
                    (payments_db, Want(SecretType.SLACK_WEBHOOK_URL)),
                ),
                FileSpec("docker-compose.yml", Context.YAML, (payments_db,)),
                FileSpec("scripts/release.sh", Context.SHELL, (ci_token,)),
                FileSpec(
                    "keys/deploy.pem",
                    Context.PEM,
                    (Want(SecretType.PRIVATE_KEY_EC),),
                    Placement.DELETED_FILE,
                ),
                FileSpec(
                    "config/sso.json", Context.JSON, (Want(SecretType.JWT),), Placement.SIDE_BRANCH
                ),
                FileSpec(None, Context.PEM, (Want(BaitKind.FIXTURE_KEY),)),
                FileSpec("docs/aws-setup.md", Context.MARKDOWN, (Want(BaitKind.AWS_EXAMPLE),)),
            ),
        ),
        RepoSpec(
            "acme/platform",
            commits=8 * scale,
            start_day=120,
            span_days=900,
            snapshots=1,
            rename=True,
            ignored=("/tools/deploy-cli/",),
            files=(
                FileSpec(
                    "config/app.ini",
                    Context.INI,
                    (Want(SecretType.MYSQL_URL), Want(SecretType.PASSWORD)),
                ),
                FileSpec(
                    "web/config.js",
                    Context.JAVASCRIPT,
                    (Want(SecretType.SLACK_BOT_TOKEN),),
                    Placement.HISTORY_ONLY,
                ),
                FileSpec("web/branding.js", Context.JAVASCRIPT, (Want(BaitKind.BASE64_IMAGE),)),
            ),
        ),
        RepoSpec(
            "acme/platform/tools/deploy-cli",
            RepoKind.NESTED,
            commits=6 * scale,
            start_day=300,
            span_days=500,
            files=(
                FileSpec(".aws/credentials", Context.AWS_CREDENTIALS, (aws_pair,)),
                FileSpec("README.md", Context.MARKDOWN, (Want(BaitKind.AWS_EXAMPLE),)),
                FileSpec(
                    "docs/bootstrap.md",
                    Context.MARKDOWN,
                    (Want(SecretType.PRIVATE_KEY_OPENSSH),),
                    Placement.DELETED_FILE,
                ),
            ),
        ),
        RepoSpec(
            "acme/design-system",
            RepoKind.CLEAN,
            commits=6 * scale,
            start_day=200,
            span_days=700,
            releases=2,
            binary=True,
        ),
        RepoSpec(
            "globex/payments",
            team=3,
            commits=9 * scale,
            start_day=20,
            span_days=1100,
            merges=1,
            snapshots=1,
            side_branch="reporting-v2",
            files=(
                FileSpec(".env", Context.ENV, (ci_token, Want(SecretType.MONGODB_URL))),
                FileSpec(
                    "reporting/settings.yml",
                    Context.YAML,
                    (Want(SecretType.GENERIC_API_KEY),),
                    Placement.SIDE_BRANCH,
                ),
                FileSpec("deploy/checksums.yml", Context.YAML, (Want(BaitKind.SHA256_HEX),)),
                FileSpec(
                    "deploy/aws.ini",
                    Context.INI,
                    (Want(SecretType.AWS_ACCESS_KEY_ID),),
                    Placement.WORKTREE_REF,
                ),
            ),
        ),
        RepoSpec(
            "globex/docs-site",
            RepoKind.CLEAN,
            commits=7 * scale,
            start_day=60,
            span_days=800,
            releases=1,
            rename=True,
        ),
        RepoSpec(
            "labs/data-science/2022/q3/forecasting",
            commits=6 * scale,
            start_day=500,
            span_days=400,
            files=(
                FileSpec("certs/service.key", Context.PEM, (Want(SecretType.PRIVATE_KEY_PKCS8),)),
                FileSpec("notebooks/tracing.py", Context.PYTHON, (Want(BaitKind.UUID),)),
                FileSpec(
                    ".env.local",
                    Context.ENV,
                    (Want(SecretType.AWS_ACCESS_KEY_ID),),
                    Placement.REFLOG_ONLY,
                ),
            ),
        ),
        RepoSpec(
            "archive/legacy-billing.git",
            RepoKind.BARE,
            commits=7 * scale,
            span_days=600,
            releases=1,
            files=(
                FileSpec("config/database.yml", Context.YAML, (Want(SecretType.POSTGRES_URL),)),
                FileSpec(
                    "config/secrets.json",
                    Context.JSON,
                    (Want(SecretType.PASSWORD),),
                    Placement.HISTORY_ONLY,
                ),
                FileSpec("deploy/id_ed25519", Context.PEM, (Want(SecretType.PRIVATE_KEY_OPENSSH),)),
            ),
        ),
    ]


_SECRET_FILES: tuple[tuple[str, Context, tuple[SecretType, ...]], ...] = (
    (".env", Context.ENV, (SecretType.AWS_ACCESS_KEY_ID,)),
    (".env.production", Context.ENV, (SecretType.POSTGRES_URL, SecretType.SLACK_BOT_TOKEN)),
    ("config/database.yml", Context.YAML, (SecretType.POSTGRES_URL,)),
    ("config/mongo.yml", Context.YAML, (SecretType.MONGODB_URL,)),
    ("config/settings.py", Context.PYTHON, (SecretType.PASSWORD, SecretType.GENERIC_API_KEY)),
    ("src/config.js", Context.JAVASCRIPT, (SecretType.SLACK_WEBHOOK_URL,)),
    ("config/app.ini", Context.INI, (SecretType.MYSQL_URL, SecretType.PASSWORD)),
    ("config/services.json", Context.JSON, (SecretType.JWT, SecretType.GITHUB_PAT)),
    ("scripts/publish.sh", Context.SHELL, (SecretType.GITHUB_PAT,)),
    (".aws/credentials", Context.AWS_CREDENTIALS, (SecretType.AWS_ACCESS_KEY_ID,)),
    ("keys/server.key", Context.PEM, (SecretType.PRIVATE_KEY_EC,)),
    ("certs/client.pem", Context.PEM, (SecretType.PRIVATE_KEY_PKCS8,)),
    ("deploy/id_ed25519", Context.PEM, (SecretType.PRIVATE_KEY_OPENSSH,)),
    ("docs/access.md", Context.MARKDOWN, (SecretType.PRIVATE_KEY_OPENSSH,)),
)
_BAIT_FILES: tuple[tuple[str | None, Context, BaitKind], ...] = (
    ("docs/aws.md", Context.MARKDOWN, BaitKind.AWS_EXAMPLE),
    (".env.example", Context.ENV, BaitKind.PLACEHOLDER),
    ("deploy/checksums.yml", Context.YAML, BaitKind.SHA256_HEX),
    ("src/tracing.py", Context.PYTHON, BaitKind.UUID),
    ("package-lock.json", Context.JSON, BaitKind.LOCKFILE_INTEGRITY),
    ("web/branding.js", Context.JAVASCRIPT, BaitKind.BASE64_IMAGE),
    (None, Context.PEM, BaitKind.FIXTURE_KEY),
)
_ANY_PLACEMENT = (
    Placement.HEAD,
    Placement.HEAD,
    Placement.HISTORY_ONLY,
    Placement.DELETED_FILE,
    Placement.SIDE_BRANCH,
)
_ORGS = {
    Size.DEMO: ("acme", "globex", "initech", "vandelay", "wonka"),
    Size.LARGE: ("acme", "globex", "initech", "vandelay", "wonka", "hooli", "tyrell", "soylent"),
}
_REPO_NAMES = (
    "billing-api",
    "auth-service",
    "mobile-app",
    "data-pipeline",
    "infra",
    "website",
    "analytics",
    "notifications",
    "search",
    "admin-portal",
    "etl-jobs",
    "monitoring",
    "checkout",
    "identity",
)
_GIANTS = ("initech/monolith", "wonka/legacy-erp", "globex/data-warehouse")
_EXTRA_COUNTS = {Size.DEMO: ((2, 4), (8, 24)), Size.LARGE: ((3, 6), (15, 60))}


def _random_files(rng: Rng, org: str, count: int) -> tuple[FileSpec, ...]:
    pool = list(_SECRET_FILES)
    files = []
    for _ in range(count):
        path, context, kinds = pool.pop(rng.below(len(pool)))
        choices = [
            p
            for p in _ANY_PLACEMENT
            if not (context in _BLOCK_CONTEXTS and p is Placement.HISTORY_ONLY)
        ]
        shared = rng.below(4) == 0
        wants = tuple(
            Want(kind, f"{org}/shared/{kind}" if shared and n == 0 else None)
            for n, kind in enumerate(kinds)
        )
        files.append(FileSpec(path, context, wants, rng.choice(choices)))
    if rng.below(2) == 0:
        bait_path, bait_context, bait = rng.choice(_BAIT_FILES)
        files.append(FileSpec(bait_path, bait_context, (Want(bait),)))
    return tuple(files)


def _extras(rng: Rng, size: Size) -> list[RepoSpec]:
    per_org, commits = _EXTRA_COUNTS[size]
    taken = {spec.rel for spec in _core(1)}
    specs: list[RepoSpec] = []
    for org in _ORGS[size]:
        names = [name for name in _REPO_NAMES if f"{org}/{name}" not in taken]
        for _ in range(rng.between(*per_org)):
            rel = f"{org}/{names.pop(rng.below(len(names)))}"
            clean = rng.below(5) == 0
            files = () if clean else _random_files(rng, org, rng.between(1, 3))
            specs.append(
                RepoSpec(
                    rel,
                    RepoKind.CLEAN if clean else RepoKind.NORMAL,
                    files,
                    commits=rng.between(*commits),
                    team=rng.between(2, 4),
                    start_day=rng.below(500),
                    span_days=rng.between(200, 900),
                    merges=rng.below(3),
                    releases=rng.below(3),
                    snapshots=rng.below(2),
                    rename=rng.below(2) == 0,
                    binary=rng.below(3) == 0,
                )
            )
    if size is Size.LARGE:
        for rel in _GIANTS:
            org = rel.split("/")[0]
            specs.append(
                RepoSpec(
                    rel,
                    files=_random_files(rng, org, rng.between(3, 5)),
                    commits=rng.between(2000, 2300),
                    team=6,
                    start_day=rng.below(30),
                    span_days=1300,
                    merges=rng.between(15, 25),
                    releases=rng.between(8, 12),
                    snapshots=rng.between(3, 6),
                    rename=True,
                    binary=True,
                    big_files=2,
                )
            )
    return specs
