import os
import re
import threading
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from gitmortem.db.models import UploadRepoRefusal
from gitmortem.scanning.settings import UploadLimits
from gitmortem.trees import remove_tree
from gitmortem.uploads.found import LOOSE, PACK, FoundRepo
from gitmortem.uploads.ziplist import DEFLATED, STORED, ZipEntry

_CHUNK = 64 << 10
_ROOT_FILES = frozenset({b"HEAD", b"packed-refs", b"shallow"})
_SUPERSCRIPT = rb"\xc2[\xb9\xb2\xb3]"
_RESERVED = re.compile(
    rb"(?is)(?:con|prn|aux|nul|conin\$|conout\$|(?:com|lpt)(?:[0-9]|"
    + _SUPERSCRIPT
    + rb"))(?:\..*)?"
)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class ExtractCancelled(Exception):
    def __init__(self) -> None:
        super().__init__("extraction was cancelled")


@dataclass(frozen=True)
class Extracted:
    git_dir: Path
    written_bytes: int


def allowed_git_path(rel: bytes) -> bool:
    if rel.endswith(b".lock"):
        return False
    if rel in _ROOT_FILES or LOOSE.fullmatch(rel) or PACK.fullmatch(rel):
        return True
    segments = rel.split(b"/")
    if segments[0] in (b"refs", b"logs"):
        return len(segments) > 1
    if segments[0] == b"worktrees" and len(segments) >= 3:
        own = segments[2:]
        return own in ([b"HEAD"], [b"logs", b"HEAD"]) or (own[0] == b"refs" and len(own) > 1)
    return False


def _plain_path(rel: bytes) -> bool:
    if not rel or rel.startswith(b"/") or b"\\" in rel or b":" in rel or b"\x00" in rel:
        return False
    for segment in rel.split(b"/"):
        if segment in (b"", b".", b"..") or segment.lower() == b".git":
            return False
        if _RESERVED.fullmatch(segment) or segment.endswith((b" ", b".")):
            return False
    return True


def _write(
    reader: BinaryIO, entry: ZipEntry, target: int, cancel: threading.Event
) -> int | UploadRepoRefusal:
    if entry.method not in (STORED, DEFLATED):
        return UploadRepoRefusal.UNREADABLE
    reader.seek(entry.data_offset)
    left = entry.compressed
    inflater = zlib.decompressobj(-zlib.MAX_WBITS) if entry.method == DEFLATED else None
    written = 0
    crc = 0
    while left > 0 or (inflater is not None and inflater.unconsumed_tail):
        if cancel.is_set():
            raise ExtractCancelled
        if inflater is not None and inflater.unconsumed_tail:
            raw = inflater.unconsumed_tail
        else:
            raw = reader.read(min(_CHUNK, left))
            if not raw:
                return UploadRepoRefusal.UNREADABLE
            left -= len(raw)
        if inflater is None:
            data = raw
        else:
            try:
                data = inflater.decompress(raw, entry.size - written + 1)
            except zlib.error:
                return UploadRepoRefusal.UNREADABLE
        written += len(data)
        if written > entry.size:
            return UploadRepoRefusal.UNREADABLE
        crc = zlib.crc32(data, crc)
        os.write(target, data)
    if written != entry.size or crc != entry.crc:
        return UploadRepoRefusal.UNREADABLE
    return written


def extract_git_dir(
    reader: BinaryIO,
    entries: Sequence[ZipEntry],
    repo: FoundRepo,
    into: Path,
    *,
    limits: UploadLimits,
    cancel: threading.Event,
) -> Extracted | UploadRepoRefusal:
    prefix = repo.git_prefix + b"/" if repo.git_prefix else b""
    chosen: list[tuple[bytes, ZipEntry]] = []
    for entry in entries:
        if not entry.name.startswith(prefix) or entry.is_folder:
            continue
        rel = entry.name[len(prefix) :]
        if not allowed_git_path(rel):
            continue
        if not _plain_path(rel):
            return UploadRepoRefusal.BAD_ENTRY_NAME
        if entry.is_special:
            return UploadRepoRefusal.LINK_OR_DEVICE
        if entry.size > limits.ratio * max(entry.compressed, 1):
            return UploadRepoRefusal.TOO_COMPRESSED
        chosen.append((rel, entry))
    declared = sum(entry.size for _, entry in chosen)
    if declared > limits.ratio * max(sum(entry.compressed for _, entry in chosen), 1):
        return UploadRepoRefusal.TOO_COMPRESSED
    into.mkdir(mode=0o700)
    try:
        made = _extract(reader, chosen, into, limits=limits, cancel=cancel)
    except BaseException:
        remove_tree(into, ignore_errors=True)
        raise
    if isinstance(made, UploadRepoRefusal):
        remove_tree(into, ignore_errors=True)
    return made


def _extract(
    reader: BinaryIO,
    chosen: Sequence[tuple[bytes, ZipEntry]],
    into: Path,
    *,
    limits: UploadLimits,
    cancel: threading.Event,
) -> Extracted | UploadRepoRefusal:
    written_total = 0
    compressed_total = 0
    for rel, entry in chosen:
        if cancel.is_set():
            raise ExtractCancelled
        parts = [os.fsdecode(part) for part in rel.split(b"/")]
        parent = into
        for part in parts[:-1]:
            parent = parent / part
            parent.mkdir(mode=0o700, exist_ok=True)
        target = parent / parts[-1]
        try:
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY, 0o600
            )
        except FileExistsError:
            return UploadRepoRefusal.BAD_ENTRY_NAME
        try:
            done = _write(reader, entry, descriptor, cancel)
        finally:
            os.close(descriptor)
        if isinstance(done, UploadRepoRefusal):
            return done
        written_total += done
        compressed_total += entry.compressed
        if written_total > limits.ratio * max(compressed_total, 1):
            return UploadRepoRefusal.TOO_COMPRESSED
    return Extracted(into, written_total)
