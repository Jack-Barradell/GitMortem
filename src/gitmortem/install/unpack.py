import os
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import IO, Literal

__all__ = ["UnpackRefused", "member"]

_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
_NEW_FILE |= getattr(os, "O_BINARY", 0)
_BLOCK = 64 << 10


class UnpackRefused(Exception):
    pass


def _copy(source: IO[bytes], dest: Path, name: str, max_bytes: int) -> None:
    fd = os.open(dest, _NEW_FILE, 0o600)
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while block := source.read(_BLOCK):
                written += len(block)
                if written > max_bytes:
                    raise UnpackRefused(f"{name} is over {max_bytes} bytes")
                out.write(block)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise


def _from_tar(archive: Path, name: str, dest: Path, max_bytes: int) -> None:
    with tarfile.open(archive, mode="r:gz") as tar:
        found = [info for info in tar.getmembers() if info.name == name]
        if len(found) != 1:
            raise UnpackRefused(f"the archive holds {len(found)} files named {name}, not 1")
        if not found[0].isreg():
            raise UnpackRefused(f"{name} in the archive is not a plain file")
        source = tar.extractfile(found[0])
        if source is None:
            raise UnpackRefused(f"{name} in the archive cannot be read")
        with source:
            _copy(source, dest, name, max_bytes)


def _from_zip(archive: Path, name: str, dest: Path, max_bytes: int) -> None:
    with zipfile.ZipFile(archive) as zipped:
        found = [info for info in zipped.infolist() if info.filename == name]
        if len(found) != 1:
            raise UnpackRefused(f"the archive holds {len(found)} files named {name}, not 1")
        kind = stat.S_IFMT(found[0].external_attr >> 16)
        if found[0].is_dir() or (kind and kind != stat.S_IFREG):
            raise UnpackRefused(f"{name} in the archive is not a plain file")
        with zipped.open(found[0]) as source:
            _copy(source, dest, name, max_bytes)


def member(
    archive: Path, name: str, dest: Path, *, kind: Literal["tar.gz", "zip"], max_bytes: int
) -> None:
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("a member is named by a plain file name")
    if kind == "tar.gz":
        _from_tar(archive, name, dest, max_bytes)
    else:
        _from_zip(archive, name, dest, max_bytes)
