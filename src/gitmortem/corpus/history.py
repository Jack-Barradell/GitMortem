import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from gitmortem.gitrun import GitRunner

SYMLINK_MODE = 0o120000

_NO_REFLOG = [("core.logAllRefUpdates", "false")]
_REF_COMMITTER = {
    "GIT_COMMITTER_NAME": "GitMortem Corpus",
    "GIT_COMMITTER_EMAIL": "corpus@example.com",
    "GIT_COMMITTER_DATE": "1609750800 +0000",
}


@dataclass(frozen=True)
class Person:
    name: str
    email: str


@dataclass(frozen=True)
class FileChange:
    op: Literal["modify", "delete", "rename"]
    path: bytes
    content: bytes | None = field(default=None, repr=False)
    mode: int = 0o100644
    new_path: bytes | None = None


@dataclass(frozen=True)
class CommitSpec:
    mark: int
    branch: str
    author: Person
    when: int
    message: str
    parents: tuple[int, ...]
    changes: tuple[FileChange, ...]


@dataclass(frozen=True)
class TagSpec:
    name: str
    target: int
    annotated: bool
    tagger: Person | None
    when: int
    message: str


@dataclass(frozen=True)
class ReflogEntry:
    old: int
    new: int
    who: Person
    when: int
    message: str


@dataclass(frozen=True)
class LinkedWorktree:
    folder: str
    head: int
    refs: dict[str, int]


@dataclass
class RepoHistory:
    commits: list[CommitSpec]
    tags: list[TagSpec]
    default_branch: str = "main"
    dropped: tuple[str, ...] = ()
    reflogs: dict[str, tuple[ReflogEntry, ...]] = field(default_factory=dict)
    worktrees: tuple[LinkedWorktree, ...] = ()


def _quote(path: bytes, *, spaces: bool = False) -> bytes:
    if not (path.startswith(b'"') or b"\n" in path or (spaces and b" " in path)):
        return path
    escaped = path.replace(b"\\", b"\\\\").replace(b'"', b'\\"').replace(b"\n", b"\\n")
    return b'"' + escaped + b'"'


def _signature(person: Person, when: int) -> bytes:
    return b"%s <%s> %d +0000" % (person.name.encode(), person.email.encode(), when)


def _ident(role: bytes, person: Person, when: int) -> bytes:
    return b"%s %s\n" % (role, _signature(person, when))


def _data(payload: bytes) -> bytes:
    return b"data %d\n%s\n" % (len(payload), payload)


def _change(change: FileChange) -> bytes:
    if change.op == "delete":
        return b"D " + _quote(change.path) + b"\n"
    if change.op == "rename":
        if change.new_path is None:
            raise ValueError("a rename needs new_path")
        return b"R " + _quote(change.path, spaces=True) + b" " + _quote(change.new_path) + b"\n"
    if change.content is None:
        raise ValueError("a modify needs content")
    return b"M %o inline %s\n%s" % (change.mode, _quote(change.path), _data(change.content))


def fast_import_stream(history: RepoHistory) -> bytes:
    if not any(commit.branch == history.default_branch for commit in history.commits):
        raise ValueError(f"no commit is on the default branch {history.default_branch}")
    out = bytearray()
    started: set[str] = set()
    for commit in history.commits:
        if len(commit.parents) > 2:
            raise ValueError("a commit has at most two parents")
        if not commit.parents and commit.branch in started:
            raise ValueError(f"a commit with no parents on {commit.branch}, which has commits")
        started.add(commit.branch)
        out += b"commit refs/heads/%s\nmark :%d\n" % (commit.branch.encode(), commit.mark)
        out += _ident(b"author", commit.author, commit.when)
        out += _ident(b"committer", commit.author, commit.when)
        out += _data(commit.message.encode())
        if commit.parents:
            out += b"from :%d\n" % commit.parents[0]
        for extra in commit.parents[1:]:
            out += b"merge :%d\n" % extra
        for change in commit.changes:
            out += _change(change)
        out += b"\n"
    for tag in history.tags:
        if tag.annotated:
            if tag.tagger is None:
                raise ValueError("an annotated tag needs a tagger")
            out += b"tag %s\nfrom :%d\n" % (tag.name.encode(), tag.target)
            out += _ident(b"tagger", tag.tagger, tag.when)
            out += _data(tag.message.encode())
        else:
            out += b"reset refs/tags/%s\nfrom :%d\n\n" % (tag.name.encode(), tag.target)
    out += b"done\n"
    return bytes(out)


def write_repo(
    runner: GitRunner,
    path: Path,
    history: RepoHistory,
    *,
    bare: bool = False,
    marks_dir: Path,
) -> dict[int, str]:
    marks_dir.mkdir(parents=True, exist_ok=True)
    path = path.resolve()
    tag = hashlib.sha256(os.fsencode(path)).hexdigest()[:16]
    template = marks_dir / "empty-template"
    template.mkdir(exist_ok=True)
    marks = marks_dir / f"{tag}.marks"

    init = [
        "init",
        "--quiet",
        f"--template={template}",
        f"--initial-branch={history.default_branch}",
        "--object-format=sha1",
    ]
    if bare:
        init.append("--bare")
    runner.run([*init, "--", str(path)], cwd=marks_dir)
    env = {"GIT_DIR": str(path if bare else path / ".git"), **_REF_COMMITTER}
    runner.run(
        ["fast-import", "--quiet", "--done", f"--export-marks={marks}"],
        cwd=path,
        stdin=fast_import_stream(history),
        extra_env=env,
        extra_config=_NO_REFLOG,
    )
    for branch in history.dropped:
        runner.run(
            ["update-ref", "-d", f"refs/heads/{branch}"],
            cwd=path,
            extra_env=env,
            extra_config=_NO_REFLOG,
        )
    if not bare:
        runner.run(
            ["reset", "--hard", "--quiet"],
            cwd=path,
            extra_env={**env, "GIT_WORK_TREE": str(path)},
            extra_config=_NO_REFLOG,
        )

    result: dict[int, str] = {}
    for line in marks.read_text().splitlines():
        mark, sha = line.split(" ")
        result[int(mark.lstrip(":"))] = sha
    git_dir = Path(env["GIT_DIR"])
    for branch, moves in history.reflogs.items():
        _write_reflog(git_dir / "logs" / "refs" / "heads" / branch, moves, result)
    for worktree in history.worktrees:
        _write_worktree(git_dir, path.parent / worktree.folder, worktree, result)
    return result


def _write_reflog(log: Path, moves: tuple[ReflogEntry, ...], oids: dict[int, str]) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    lines = b"".join(
        b"%s %s %s\t%s\n"
        % (
            oids[move.old].encode(),
            oids[move.new].encode(),
            _signature(move.who, move.when),
            move.message.encode(),
        )
        for move in moves
    )
    log.write_bytes(lines)


def _relative(target: Path, start: Path) -> str:
    return Path(os.path.relpath(target, start)).as_posix()


def _write_worktree(
    git_dir: Path, folder: Path, worktree: LinkedWorktree, oids: dict[int, str]
) -> None:
    entry = git_dir / "worktrees" / worktree.folder
    for name, mark in worktree.refs.items():
        ref = entry / name
        ref.parent.mkdir(parents=True, exist_ok=True)
        ref.write_text(oids[mark] + "\n")
    (entry / "HEAD").write_text(oids[worktree.head] + "\n")
    (entry / "commondir").write_text("../..\n")
    folder.mkdir()
    (folder / ".git").write_text(f"gitdir: {_relative(entry, folder)}\n")
    (entry / "gitdir").write_text(_relative(folder / ".git", entry) + "\n")
