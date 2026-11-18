import hashlib
import stat
from collections.abc import Iterable, Mapping
from dataclasses import replace
from pathlib import Path, PurePosixPath

from gitmortem.corpus.contexts import Context
from gitmortem.corpus.fakes import FakeSecret, SecretType
from gitmortem.corpus.history import SYMLINK_MODE, FileChange, Person, write_repo
from gitmortem.corpus.manifest import (
    HostileInfo,
    Occurrence,
    Payload,
    Placement,
    RepoEntry,
    RepoKind,
    Silencer,
)
from gitmortem.corpus.recipe import (
    FileSpec,
    PlannedRepo,
    RepoSpec,
    Values,
    Want,
    check_layout,
    plan_repo,
    realise,
)
from gitmortem.corpus.rng import Rng
from gitmortem.gitrun import GitRunner

MARKERS = "markers"
OUTSIDE = "outside"

_RUNS_CODE = "hostile/runs-code"
_SILENCES_GITLEAKS = "hostile/silences-gitleaks"
_SILENCES_GIT_SECRETS = "hostile/silences-git-secrets"
_SILENCES_TRUFFLEHOG = "hostile/silences-trufflehog"
_ODD_NAMES = "hostile/odd-names"
_ESCAPES = "hostile/escapes"
_ESCAPED_REPO = "escaped-repo"
_LINKED_REPO = "repos/hostile/linked-repo"
_HIDES_REPLACE = "hostile/hides-history-replace"
_HIDES_GRAPH = "hostile/hides-history-graph"
_FORGED_INDEX = "hostile/forged-index"
_REPLACED_BRANCH = "wip/key-rotation"

_GRAPH_NO_PARENT = 0x70000000
_PACK_INDEX_V2 = b"\xfftOc\x00\x00\x00\x02"

_LOOT_LINK = b"../../../outside/loot.txt"
_LINKED_REPO_TARGET = "../../outside/escaped-repo"
_LOOT = (
    b"Escape canary. This file lives outside the scan root, at TARGET/outside/loot.txt.\n"
    b"Anything that shows it through repos/hostile/escapes/loot.txt followed a symlink out.\n"
)

_HTML_NAME = "<img src=x onerror=alert(1)>.txt"
_ODD_FILE_NAMES = (
    "--output=x",
    _HTML_NAME,
    "notes\nfinal.env",
    b"caf\xe9.env".decode("utf-8", "surrogateescape"),
)
_HTML_AUTHOR = Person('Mallory" onmouseover="alert(1)', "mallory@example.com")
_HTML_MESSAGE = "Add the <img src=x onerror=alert(1)> notes <script>alert(1)</script>\n"

_GITLEAKS_RULES = {
    SecretType.GITHUB_PAT: "github-pat",
    SecretType.JWT: "jwt",
    SecretType.SLACK_BOT_TOKEN: "slack-bot-token",
}

_Found = list[tuple[FakeSecret, Occurrence]]


def _silenced(
    path: str, context: Context, kind: SecretType, silencer: Silencer, comment: str | None = None
) -> FileSpec:
    return FileSpec(path, context, (Want(kind),), Placement.SILENCED, (silencer,), comment)


def _specs() -> list[RepoSpec]:
    aws = Want(SecretType.AWS_ACCESS_KEY_ID)
    return [
        RepoSpec(
            _RUNS_CODE,
            RepoKind.HOSTILE,
            commits=5,
            span_days=300,
            initial_files=(FileChange("modify", b".gitattributes", b"* diff=gm\n"),),
        ),
        RepoSpec(
            _SILENCES_GITLEAKS,
            RepoKind.HOSTILE,
            commits=5,
            start_day=30,
            span_days=400,
            files=(
                _silenced(
                    "legacy/settings.py",
                    Context.PYTHON,
                    SecretType.GITHUB_PAT,
                    Silencer.GITLEAKS_CONFIG,
                ),
                _silenced(
                    "deploy/session.yml", Context.YAML, SecretType.JWT, Silencer.GITLEAKSIGNORE
                ),
                _silenced(
                    "scripts/notify.sh",
                    Context.SHELL,
                    SecretType.SLACK_BOT_TOKEN,
                    Silencer.GITLEAKS_ALLOW,
                    "gitleaks:allow",
                ),
                FileSpec("web/config.js", Context.JAVASCRIPT, (Want(SecretType.GITHUB_PAT),)),
            ),
        ),
        RepoSpec(
            _SILENCES_GIT_SECRETS,
            RepoKind.HOSTILE,
            commits=5,
            start_day=60,
            span_days=400,
            files=(
                FileSpec(
                    "deploy/legacy.env",
                    Context.ENV,
                    (aws,),
                    Placement.SILENCED,
                    (Silencer.GIT_SECRETS_ALLOWED,),
                ),
                FileSpec(
                    "ops/backup.ini",
                    Context.INI,
                    (aws,),
                    Placement.SILENCED,
                    (Silencer.GITALLOWED,),
                ),
                FileSpec(".aws/credentials", Context.AWS_CREDENTIALS, (aws,)),
            ),
        ),
        RepoSpec(
            _SILENCES_TRUFFLEHOG,
            RepoKind.HOSTILE,
            commits=5,
            start_day=90,
            span_days=400,
            files=(
                _silenced(
                    "services/reporting.py",
                    Context.PYTHON,
                    SecretType.POSTGRES_URL,
                    Silencer.TRUFFLEHOG_IGNORE,
                    "trufflehog:ignore",
                ),
                _silenced(
                    "deploy/alerts.yml",
                    Context.YAML,
                    SecretType.SLACK_WEBHOOK_URL,
                    Silencer.TRUFFLEHOG_IGNORE,
                    "trufflehog:ignore",
                ),
                FileSpec(".env", Context.ENV, (Want(SecretType.GITHUB_PAT),)),
            ),
        ),
        RepoSpec(
            _ODD_NAMES,
            RepoKind.HOSTILE,
            commits=6,
            start_day=120,
            span_days=300,
            files=tuple(
                FileSpec(name, Context.ENV, (aws,), Placement.DELETED_FILE)
                for name in _ODD_FILE_NAMES
            ),
        ),
        RepoSpec(
            _ESCAPES,
            RepoKind.HOSTILE,
            commits=4,
            start_day=150,
            span_days=200,
            initial_files=(FileChange("modify", b"loot.txt", _LOOT_LINK, SYMLINK_MODE),),
        ),
        RepoSpec(
            _ESCAPED_REPO,
            RepoKind.OUTSIDE,
            commits=4,
            start_day=10,
            span_days=300,
            files=(
                FileSpec(".env", Context.ENV, (aws,)),
                FileSpec("config/settings.py", Context.PYTHON, (Want(SecretType.GITHUB_PAT),)),
            ),
        ),
        RepoSpec(
            _HIDES_REPLACE,
            RepoKind.HOSTILE,
            commits=5,
            start_day=180,
            span_days=300,
            side_branch=_REPLACED_BRANCH,
            files=(
                FileSpec(
                    "deploy/rotation.env",
                    Context.ENV,
                    (aws,),
                    Placement.SIDE_BRANCH,
                    (Silencer.REPLACE_REF,),
                ),
                FileSpec(".aws/credentials", Context.AWS_CREDENTIALS, (aws,)),
            ),
        ),
        RepoSpec(
            _HIDES_GRAPH,
            RepoKind.HOSTILE,
            commits=5,
            start_day=210,
            span_days=300,
            plants_last=True,
            files=(
                FileSpec(
                    "config/legacy.ini",
                    Context.INI,
                    (aws,),
                    Placement.HISTORY_ONLY,
                    (Silencer.COMMIT_GRAPH,),
                ),
                FileSpec(".aws/credentials", Context.AWS_CREDENTIALS, (aws,)),
            ),
        ),
        RepoSpec(
            _FORGED_INDEX,
            RepoKind.HOSTILE,
            commits=5,
            start_day=240,
            span_days=300,
            files=(
                FileSpec(
                    "deploy/old.env",
                    Context.ENV,
                    (aws,),
                    Placement.HISTORY_ONLY,
                    (Silencer.FORGED_INDEX,),
                ),
                FileSpec(".aws/credentials", Context.AWS_CREDENTIALS, (aws,)),
            ),
        ),
    ]


def _with_html_commit(repo: PlannedRepo) -> PlannedRepo:
    mark = next(each.introduced for each in repo.planted if each.path == _HTML_NAME)
    commits = [
        replace(commit, author=_HTML_AUTHOR, message=_HTML_MESSAGE)
        if commit.mark == mark
        else commit
        for commit in repo.history.commits
    ]
    return replace(repo, history=replace(repo.history, commits=commits))


def _marker(repo: PlannedRepo, payload: Payload) -> str:
    return f"{MARKERS}/{repo.spec.rel}/{payload.value}"


def _set_config(runner: GitRunner, repo_dir: Path, key: str, value: str) -> None:
    config = repo_dir / ".git" / "config"
    runner.run(["config", "--file", str(config), "--add", key, value], cwd=runner.private_dir)


def _arm_payloads(runner: GitRunner, target: Path, repo: PlannedRepo) -> dict[Payload, str]:
    where = target / repo.path
    up = "../" * len(PurePosixPath(repo.path).parts)
    touch = {payload: f"touch {up}{_marker(repo, payload)}" for payload in Payload}
    _set_config(runner, where, "core.fsmonitor", touch[Payload.FSMONITOR] + "; true")
    _set_config(runner, where, "diff.gm.textconv", touch[Payload.TEXTCONV] + "; cat")
    _set_config(runner, where, "secrets.providers", touch[Payload.GIT_SECRETS_PROVIDER])
    hooks = where / ".git" / "hooks"
    hooks.mkdir()
    hook = hooks / "post-index-change"
    hook.write_bytes(f"#!/bin/sh\n{touch[Payload.HOOK]}\n".encode())
    hook.chmod(0o755)
    (target / MARKERS / repo.spec.rel).mkdir(parents=True)
    return {payload: _marker(repo, payload) for payload in Payload}


def _paths(found: _Found, silencer: Silencer) -> list[str]:
    return sorted({o.path for _, o in found if silencer in o.silenced_by})


def _pattern(path: str) -> str:
    return path.replace(".", "\\.")


def _arm_gitleaks(where: Path, found: _Found) -> None:
    allowed = ", ".join(
        f"'''^{_pattern(path)}$'''" for path in _paths(found, Silencer.GITLEAKS_CONFIG)
    )
    overrides = (
        'title = "repository overrides"\n\n'
        "[extend]\nuseDefault = true\n\n"
        '[allowlist]\ndescription = "reviewed legacy settings"\n'
        f"paths = [{allowed}]\n"
    )
    (where / ".gitleaks.toml").write_bytes(overrides.encode())
    fingerprints = sorted(
        f"{o.introduced}:{o.path}:{_GITLEAKS_RULES[SecretType(secret.kind)]}:{o.line}"
        for secret, o in found
        if Silencer.GITLEAKSIGNORE in o.silenced_by
    )
    (where / ".gitleaksignore").write_bytes("".join(f"{f}\n" for f in fingerprints).encode())


def _arm_git_secrets(runner: GitRunner, where: Path, found: _Found) -> None:
    def allowed(path: str) -> str:
        return f"(^|:){_pattern(path)}:"

    for path in _paths(found, Silencer.GIT_SECRETS_ALLOWED):
        _set_config(runner, where, "secrets.allowed", allowed(path))
    lines = ["# rotated long ago", *(allowed(path) for path in _paths(found, Silencer.GITALLOWED))]
    (where / ".gitallowed").write_bytes("".join(f"{line}\n" for line in lines).encode())


def _hidden(occurrences: Iterable[Occurrence], silencer: Silencer) -> tuple[str, str, str]:
    (place,) = {(o.path, o.introduced, o.removed) for o in occurrences if silencer in o.silenced_by}
    path, introduced, removed = place
    if removed is None:
        raise ValueError(f"what {silencer} hides must leave its file in a later commit")
    return path, introduced, removed


def _swap_side_tip(
    runner: GitRunner, git_dir: Path, repo: PlannedRepo, marks: Mapping[int, str], branch: str
) -> None:
    tip = next(commit for commit in repo.history.commits if commit.mark == repo.tips[branch])
    fork = marks[next(c for c in repo.history.commits if c.branch == branch).parents[0]]
    when = f"{tip.when} +0000"
    env = {
        "GIT_DIR": str(git_dir),
        "GIT_AUTHOR_NAME": tip.author.name,
        "GIT_AUTHOR_EMAIL": tip.author.email,
        "GIT_AUTHOR_DATE": when,
        "GIT_COMMITTER_NAME": tip.author.name,
        "GIT_COMMITTER_EMAIL": tip.author.email,
        "GIT_COMMITTER_DATE": when,
    }
    stand_in = runner.run(
        ["commit-tree", f"{fork}^{{tree}}", "-p", fork],
        cwd=runner.private_dir,
        stdin=tip.message.encode(),
        extra_env=env,
    ).strip()
    runner.run(
        ["update-ref", f"refs/replace/{marks[tip.mark]}", stand_in.decode()],
        cwd=runner.private_dir,
        extra_env=env,
        extra_config=[("core.logAllRefUpdates", "false")],
    )


def _commit_graph(commits: Mapping[str, tuple[str, int, tuple[str, ...]]]) -> bytes:
    ids = sorted(commits)
    position = {sha: n for n, sha in enumerate(ids)}
    level: dict[str, int] = {}
    for sha in ids:
        stack = [sha]
        while stack:
            top = stack[-1]
            waiting = [parent for parent in commits[top][2] if parent not in level]
            if waiting:
                stack += waiting
                continue
            level[top] = 1 + max((level[parent] for parent in commits[top][2]), default=0)
            stack.pop()
    fanout = b"".join(
        sum(1 for sha in ids if int(sha[:2], 16) <= byte).to_bytes(4, "big") for byte in range(256)
    )
    cdat = bytearray()
    for sha in ids:
        tree, when, parents = commits[sha]
        if len(parents) > 2:
            raise ValueError("an octopus merge needs the commit-graph's EDGE chunk")
        slots = [position[parent] for parent in parents]
        slots += [_GRAPH_NO_PARENT] * (2 - len(slots))
        cdat += bytes.fromhex(tree) + b"".join(slot.to_bytes(4, "big") for slot in slots)
        cdat += ((level[sha] << 2) | (when >> 32 & 0x3)).to_bytes(4, "big")
        cdat += (when & 0xFFFFFFFF).to_bytes(4, "big")
    chunks = [
        (b"OIDF", fanout),
        (b"OIDL", b"".join(bytes.fromhex(sha) for sha in ids)),
        (b"CDAT", bytes(cdat)),
    ]
    data = bytearray(b"CGPH" + bytes([1, 1, len(chunks), 0]))
    offset = len(data) + 12 * (len(chunks) + 1)
    for chunk_id, body in chunks:
        data += chunk_id + offset.to_bytes(8, "big")
        offset += len(body)
    data += bytes(4) + offset.to_bytes(8, "big")
    data += b"".join(body for _, body in chunks)
    return bytes(data + hashlib.sha1(data).digest())  # noqa: S324


def _cut_history(runner: GitRunner, git_dir: Path, cut: str) -> None:
    listing = runner.run(
        ["log", "--all", "--format=%H %T %ct %P"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(git_dir)},
    )
    commits: dict[str, tuple[str, int, tuple[str, ...]]] = {}
    for line in listing.decode().splitlines():
        sha, tree, when, *parents = line.split()
        commits[sha] = (tree, int(when), () if sha == cut else tuple(parents))
    graph = git_dir / "objects" / "info" / "commit-graph"
    graph.parent.mkdir(exist_ok=True)
    graph.write_bytes(_commit_graph(commits))
    graph.chmod(0o444)


def _forged_index(index: bytes, secret: str, benign: str) -> bytes:
    data = bytearray(index)
    if data[:8] != _PACK_INDEX_V2:
        raise ValueError("not a version 2 pack index")
    count = int.from_bytes(data[8 + 255 * 4 : 8 + 256 * 4], "big")
    ids_at = 8 + 256 * 4
    ids = [data[ids_at + 20 * n : ids_at + 20 * (n + 1)].hex() for n in range(count)]
    to, source = 4 * ids.index(secret), 4 * ids.index(benign)
    for table in (ids_at + 20 * count, ids_at + 24 * count):
        data[table + to : table + to + 4] = data[table + source : table + source + 4]
    data[-20:] = hashlib.sha1(data[:-20]).digest()  # noqa: S324
    return bytes(data)


def _forge_pack_index(runner: GitRunner, git_dir: Path, hidden: tuple[str, str, str]) -> None:
    env = {"GIT_DIR": str(git_dir)}
    path, introduced, removed = hidden

    def blob(commit: str) -> str:
        spec = f"{commit}:{path}"
        found = runner.run(["rev-parse", "--verify", spec], cwd=runner.private_dir, extra_env=env)
        return found.strip().decode()

    secret, benign = blob(introduced), blob(removed)
    runner.run(
        ["repack", "-a", "-d", "-F", "--window=0", "-n", "-q"],
        cwd=runner.private_dir,
        extra_env=env,
        extra_config=[
            ("pack.indexVersion", "2"),
            ("pack.writeReverseIndex", "false"),
            ("repack.writeBitmaps", "false"),
        ],
    )
    (index,) = (git_dir / "objects" / "pack").glob("*.idx")
    mode = stat.S_IMODE(index.stat().st_mode)
    index.chmod(0o644)
    index.write_bytes(_forged_index(index.read_bytes(), secret, benign))
    index.chmod(mode)


def _arm(
    runner: GitRunner,
    target: Path,
    repo: PlannedRepo,
    marks: Mapping[int, str],
    entry: RepoEntry,
    found: _Found,
) -> tuple[RepoEntry, _Found]:
    where = target / repo.path
    payloads: dict[Payload, str] = {}
    escapes: list[str] = []
    commit_count = entry.commit_count
    if repo.spec.rel == _RUNS_CODE:
        payloads = _arm_payloads(runner, target, repo)
    elif repo.spec.rel == _SILENCES_GITLEAKS:
        _arm_gitleaks(where, found)
    elif repo.spec.rel == _SILENCES_GIT_SECRETS:
        _arm_git_secrets(runner, where, found)
    elif repo.spec.rel == _ESCAPES:
        escapes = [f"{repo.path}/loot.txt"]
    elif repo.spec.kind is RepoKind.OUTSIDE:
        escapes = [_LINKED_REPO]
    elif repo.spec.rel == _HIDES_REPLACE:
        _swap_side_tip(runner, where / ".git", repo, marks, _REPLACED_BRANCH)
        commit_count += 1
    elif repo.spec.rel == _HIDES_GRAPH:
        _, _, removed = _hidden((o for _, o in found), Silencer.COMMIT_GRAPH)
        _cut_history(runner, where / ".git", removed)
    elif repo.spec.rel == _FORGED_INDEX:
        hidden = _hidden((o for _, o in found), Silencer.FORGED_INDEX)
        _forge_pack_index(runner, where / ".git", hidden)
        found = [
            (secret, o.model_copy(update={"detected_by": []}))
            if Silencer.FORGED_INDEX in o.silenced_by
            else (secret, o)
            for secret, o in found
        ]
    used = {silencer for _, o in found for silencer in o.silenced_by}
    info = HostileInfo(
        payloads=payloads,
        silencers=[silencer for silencer in Silencer if silencer in used],
        escapes=escapes,
        integrity_fails=repo.spec.rel == _FORGED_INDEX,
    )
    return entry.model_copy(update={"hostile": info, "commit_count": commit_count}), found


def plant_hostile(
    runner: GitRunner, target: Path, rng: Rng, values: Values
) -> tuple[list[RepoEntry], _Found]:
    planned = [plan_repo(spec, values, rng.derive(spec.rel)) for spec in _specs()]
    check_layout([repo for repo in planned if repo.spec.kind is not RepoKind.OUTSIDE])
    planned = [_with_html_commit(r) if r.spec.rel == _ODD_NAMES else r for r in planned]

    (target / OUTSIDE).mkdir()
    (target / OUTSIDE / "loot.txt").write_bytes(_LOOT)
    marks_dir = runner.private_dir / "marks"
    entries = []
    found: _Found = []
    for repo in planned:
        marks = write_repo(runner, target / repo.path, repo.history, marks_dir=marks_dir)
        entry, occurrences = _arm(runner, target, repo, marks, *realise(repo, marks))
        entries.append(entry)
        found += occurrences
    (target / _LINKED_REPO).symlink_to(_LINKED_REPO_TARGET, target_is_directory=True)
    return entries, found
