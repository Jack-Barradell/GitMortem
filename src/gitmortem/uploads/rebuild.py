import hashlib
import os
import re
import shutil
import tempfile
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path

from gitmortem.db.models import UploadRepoRefusal
from gitmortem.gitrun import GitCancelled, GitError, GitRunner, shadow_problem
from gitmortem.trees import remove_tree
from gitmortem.uploads.extract import Extracted
from gitmortem.uploads.packscan import PackRefused, PackScanCancelled, check_pack

MAX_LOOSE_BYTES = 256 << 20
_CHUNK = 64 << 10
_SHA1 = re.compile(rb"[0-9a-f]{40}")
_SHA256 = re.compile(rb"[0-9a-f]{64}")
_LOOSE_DIR = re.compile(r"[0-9a-f]{2}")
_LOOSE_NAME = re.compile(r"[0-9a-f]{38}")
_PACK = re.compile(r"pack-[0-9a-f]{40}\.pack")
MAX_REF_FILE = 64 << 10
MAX_PACKED_REFS = 64 << 20
MAX_REFLOG = 64 << 20
_BAD_COMPONENT = re.compile(rb"^\.|\.lock$|\.\.|@\{|[\x00-\x20\x7f~^:?*\[\\]")
_WORKTREE_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}")


@dataclass(frozen=True)
class Rebuilt:
    git_dir: Path
    commits: int | None
    dropped_objects: int


def valid_refname(name: bytes) -> bool:
    if not name.startswith(b"refs/") or name.endswith((b"/", b".")) or name == b"@":
        return False
    components = name.split(b"/")
    return all(part and not _BAD_COMPONENT.search(part) for part in components)


def _id_or_symref(content: bytes) -> bytes | None:
    line = content.strip()
    if _SHA1.fullmatch(line):
        return line + b"\n"
    if line.startswith(b"ref: ") and valid_refname(line[5:].strip()):
        return b"ref: " + line[5:].strip() + b"\n"
    return None


def _small(path: Path, limit: int) -> bytes | None:
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "wb") as out:
        out.write(data)


def _refusal(extracted: Path) -> UploadRepoRefusal | None:
    if (extracted / "shallow").exists():
        return UploadRepoRefusal.SHALLOW
    pack = extracted / "objects" / "pack"
    if pack.is_dir() and any(p.suffix == ".promisor" for p in pack.iterdir()):
        return UploadRepoRefusal.PARTIAL_CLONE
    if pack.is_dir() and any(len(p.stem) == len("pack-") + 64 for p in pack.iterdir()):
        return UploadRepoRefusal.SHA256
    objects = extracted / "objects"
    if objects.is_dir():
        for folder in objects.iterdir():
            if _LOOSE_DIR.fullmatch(folder.name) and any(
                len(p.name) == 62 for p in folder.iterdir()
            ):
                return UploadRepoRefusal.SHA256
    for path in [extracted / "HEAD", extracted / "packed-refs", *(extracted / "refs").rglob("*")]:
        if path.is_file():
            data = _small(path, MAX_PACKED_REFS) or b""
            if any(_SHA256.fullmatch(word) for word in re.split(rb"[\s^]+", data)):
                return UploadRepoRefusal.SHA256
    return None


def _loose_ok(path: Path, name: str) -> bool:
    inflater = zlib.decompressobj()
    digest = hashlib.sha1()  # noqa: S324
    total = 0
    try:
        with path.open("rb") as src:
            while chunk := src.read(_CHUNK):
                data = inflater.decompress(chunk, MAX_LOOSE_BYTES - total + 1)
                total += len(data)
                if total > MAX_LOOSE_BYTES or inflater.unconsumed_tail:
                    return False
                digest.update(data)
        tail = inflater.flush()
        digest.update(tail)
        total += len(tail)
    except (OSError, zlib.error):
        return False
    return total <= MAX_LOOSE_BYTES and inflater.eof and digest.hexdigest() == name


def _git(
    runner: GitRunner, git_dir: Path, args: list[str], *, timeout: float, cancel: threading.Event
) -> bytes:
    return runner.run(
        args,
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(git_dir)},
        timeout=timeout,
        cancel=cancel,
    )


def _carry_objects(
    runner: GitRunner,
    source: Path,
    into: Path,
    *,
    timeout: float,
    cancel: threading.Event,
    ratio: int,
) -> int:
    dropped = 0
    pack_in = source / "objects" / "pack"
    pack_out = into / "objects" / "pack"
    if pack_in.is_dir():
        for pack in sorted(pack_in.iterdir()):
            if not _PACK.fullmatch(pack.name):
                continue
            try:
                check_pack(pack, most_bytes=MAX_LOOSE_BYTES, ratio=ratio, cancel=cancel)
            except PackScanCancelled:
                raise GitCancelled("carry") from None
            target = pack_out / pack.name
            shutil.copyfile(pack, target)
            try:
                _git(runner, into, ["index-pack", str(target)], timeout=timeout, cancel=cancel)
            except GitError:
                if cancel.is_set():
                    raise
                for leftover in pack_out.glob(target.stem + ".*"):
                    leftover.unlink()
                dropped += 1
    objects = source / "objects"
    if objects.is_dir():
        for folder in sorted(objects.iterdir()):
            if not folder.is_dir() or not _LOOSE_DIR.fullmatch(folder.name):
                continue
            for loose in sorted(folder.iterdir()):
                if cancel.is_set():
                    raise GitCancelled("carry")
                if not _LOOSE_NAME.fullmatch(loose.name):
                    continue
                if not _loose_ok(loose, folder.name + loose.name):
                    dropped += 1
                    continue
                out = into / "objects" / folder.name / loose.name
                out.parent.mkdir(mode=0o700, exist_ok=True)
                shutil.copyfile(loose, out)
    return dropped


def _reflog(data: bytes) -> bytes:
    kept = []
    for line in data.split(b"\n"):
        if (
            len(line) > 82
            and _SHA1.fullmatch(line[:40])
            and line[40:41] == b" "
            and _SHA1.fullmatch(line[41:81])
        ):
            kept.append(line)
    return b"".join(line + b"\n" for line in kept)


def _carry_refs(source: Path, into: Path, base: str = "") -> None:
    refs = source / "refs"
    if refs.is_dir():
        for path in sorted(refs.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            name = os.fsencode(path.relative_to(source).as_posix())
            content = _small(path, MAX_REF_FILE)
            canonical = None if content is None else _id_or_symref(content)
            if valid_refname(name) and canonical is not None:
                _write_new(into / path.relative_to(source), canonical)
    logs = source / "logs"
    if logs.is_dir():
        for path in sorted(logs.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(logs).as_posix().encode()
            if rel != b"HEAD" and not valid_refname(rel):
                continue
            data = _small(path, MAX_REFLOG)
            if data is not None and (kept := _reflog(data)):
                _write_new(into / "logs" / path.relative_to(logs), kept)


def _packed_refs(data: bytes) -> bytes:
    kept: dict[bytes, bytes] = {}
    for line in data.split(b"\n"):
        if line.startswith((b"^", b"#")):
            continue
        oid, _, name = line.partition(b" ")
        if _SHA1.fullmatch(oid) and valid_refname(name):
            kept.setdefault(name, oid)
    lines = [b"# pack-refs with: sorted"]
    lines += [kept[name] + b" " + name for name in sorted(kept)]
    return b"\n".join(lines) + b"\n"


def rebuild(
    runner: GitRunner,
    extracted: Extracted,
    into: Path,
    *,
    timeout: float,
    cancel: threading.Event,
    ratio: int,
) -> Rebuilt | UploadRepoRefusal:
    source = extracted.git_dir
    refused = _refusal(source)
    if refused is not None:
        return refused
    head = _small(source / "HEAD", MAX_REF_FILE)
    canonical_head = None if head is None else _id_or_symref(head)
    if canonical_head is None:
        return UploadRepoRefusal.NOT_A_REPO
    template = Path(tempfile.mkdtemp(dir=runner.private_dir, prefix="template-"))
    try:
        _git(
            runner,
            into,
            ["init", "--bare", "-q", f"--template={template}"],
            timeout=timeout,
            cancel=cancel,
        )
    finally:
        remove_tree(template, ignore_errors=True)
    _git(runner, into, ["config", "core.commitGraph", "false"], timeout=timeout, cancel=cancel)
    try:
        dropped = _carry_objects(runner, source, into, timeout=timeout, cancel=cancel, ratio=ratio)
    except PackRefused:
        return UploadRepoRefusal.TOO_COMPRESSED
    (into / "HEAD").write_bytes(canonical_head)
    _carry_refs(source, into)
    packed = _small(source / "packed-refs", MAX_PACKED_REFS)
    if packed is not None:
        _write_new(into / "packed-refs", _packed_refs(packed))
    worktrees = source / "worktrees"
    if worktrees.is_dir():
        for folder in sorted(worktrees.iterdir()):
            if not folder.is_dir() or not _WORKTREE_ID.fullmatch(folder.name):
                continue
            wt_head = _small(folder / "HEAD", MAX_REF_FILE)
            wt_canonical = None if wt_head is None else _id_or_symref(wt_head)
            if wt_canonical is None:
                continue
            out = into / "worktrees" / folder.name
            _write_new(out / "HEAD", wt_canonical)
            _write_new(out / "commondir", b"../..\n")
            _write_new(out / "gitdir", os.fsencode(out / "no-checkout" / ".git") + b"\n")
            _carry_refs(folder, out)
    if shadow_problem(runner, into, timeout=timeout) is not None:
        return UploadRepoRefusal.NOT_A_REPO
    try:
        counted = _git(
            runner,
            into,
            ["rev-list", "--all", "--reflog", "--count"],
            timeout=timeout,
            cancel=cancel,
        )
        commits: int | None = int(counted)
    except GitError:
        if cancel.is_set():
            raise
        commits = None
    return Rebuilt(into, commits, dropped)
