import threading
from collections.abc import Iterator, Sequence
from pathlib import Path

from gitmortem.gitread import FULL_HEX, git_env
from gitmortem.gitrun import GitRunner

__all__ = ["BATCH_BYTES", "missing_objects", "object_batches", "read_records"]

BATCH_BYTES = 16 << 20
_SIZE_LINE = 80


def _header(oid: str, kind: str, size: int) -> bytes:
    return f"{oid} {kind} {size}\n".encode("ascii")


def read_records(
    out: bytes, asked: Sequence[tuple[str, int]], kind: str
) -> Iterator[tuple[str, bytes]]:
    at = 0
    for oid, size in asked:
        header = _header(oid, kind, size)
        start = at + len(header)
        if out[at:start] != header or out[start + size : start + size + 1] != b"\n":
            return
        yield oid, out[start : start + size]
        at = start + size + 1


def _sizes(
    runner: GitRunner,
    git_dir: Path,
    ids: Sequence[str],
    *,
    kind: str,
    max_size: int,
    timeout: float,
    cancel: threading.Event | None,
) -> list[tuple[str, int]]:
    out = runner.run(
        ["cat-file", "--batch-check"],
        cwd=runner.private_dir,
        stdin="".join(f"{oid}\n" for oid in ids).encode("ascii"),
        timeout=timeout,
        cancel=cancel,
        extra_env=git_env(git_dir),
        max_stdout=len(ids) * _SIZE_LINE,
    )
    sizes = []
    wanted = kind.encode("ascii")
    for oid, line in zip(ids, out.split(b"\n"), strict=False):
        parts = line.split(b" ")
        if parts[0] != oid.encode("ascii"):
            break
        is_kind = len(parts) == 3 and parts[1] == wanted and parts[2].isdigit()
        if is_kind and int(parts[2]) <= max_size:
            sizes.append((oid, int(parts[2])))
    return sizes


def missing_objects(
    runner: GitRunner,
    git_dir: Path,
    ids: Sequence[str],
    *,
    timeout: float,
    cancel: threading.Event | None = None,
) -> set[str]:
    asked = [oid for oid in dict.fromkeys(ids) if FULL_HEX.fullmatch(oid)]
    if not asked:
        return set()
    out = runner.run(
        ["cat-file", "--batch-check"],
        cwd=runner.private_dir,
        stdin="".join(f"{oid}\n" for oid in asked).encode("ascii"),
        timeout=timeout,
        cancel=cancel,
        extra_env=git_env(git_dir),
        max_stdout=len(asked) * _SIZE_LINE,
    )
    missing: set[str] = set()
    for oid, line in zip(asked, out.split(b"\n"), strict=False):
        parts = line.split(b" ")
        if parts[0] != oid.encode("ascii"):
            break
        if parts[1:] == [b"missing"]:
            missing.add(oid)
    return missing


def _batches(sizes: Sequence[tuple[str, int]]) -> Iterator[list[tuple[str, int]]]:
    batch: list[tuple[str, int]] = []
    held = 0
    for oid, size in sizes:
        if batch and held + size > BATCH_BYTES:
            yield batch
            batch, held = [], 0
        batch.append((oid, size))
        held += size
    if batch:
        yield batch


def object_batches(
    runner: GitRunner,
    git_dir: Path,
    ids: Sequence[str],
    *,
    kind: str,
    max_size: int,
    timeout: float,
    cancel: threading.Event | None = None,
) -> Iterator[tuple[str, bytes]]:
    asked = [oid for oid in dict.fromkeys(ids) if FULL_HEX.fullmatch(oid)]
    if not asked:
        return
    sizes = _sizes(
        runner,
        git_dir,
        asked,
        kind=kind,
        max_size=max_size,
        timeout=timeout,
        cancel=cancel,
    )
    for batch in _batches(sizes):
        out = runner.run(
            ["cat-file", "--batch"],
            cwd=runner.private_dir,
            stdin="".join(f"{oid}\n" for oid, _ in batch).encode("ascii"),
            timeout=timeout,
            cancel=cancel,
            extra_env=git_env(git_dir),
            max_stdout=sum(len(_header(oid, kind, size)) + size + 1 for oid, size in batch),
        )
        yield from read_records(out, batch, kind)
