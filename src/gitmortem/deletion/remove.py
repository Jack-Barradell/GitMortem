import errno
import os
import shutil
import stat
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from gitmortem.trees import remove_file, writable_again

_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_NOT_FOLLOWED = {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}
_ODD = {b"", b".", b".."}


class RemoveFailure(StrEnum):
    REPARSE_POINT = "reparse_point"
    NOT_CONTAINED = "not_contained"
    OS_ERROR = "os_error"


def _fd_safe() -> bool:
    return bool(shutil.rmtree.avoids_symlink_attacks) and os.open in os.supports_dir_fd


def _gone_is_fine(function: Callable[..., object], path: str | bytes, exc: BaseException) -> None:
    if not isinstance(exc, FileNotFoundError):
        writable_again(function, path, exc)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _has_reparse_point(folder: Path) -> bool:
    pending = [folder]
    while pending:
        with os.scandir(pending.pop()) as listing:
            for entry in listing:
                if entry.is_symlink() or entry.is_junction():
                    return True
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
    return False


def _empty(folder_fd: int) -> None:
    for name in os.listdir(folder_fd):
        try:
            info = os.stat(name, dir_fd=folder_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(name, dir_fd=folder_fd, onexc=_gone_is_fine)
        else:
            try:
                os.unlink(name, dir_fd=folder_fd)
            except FileNotFoundError:
                continue


def _identity_of(info: os.stat_result) -> tuple[int, int] | None:
    return None if info.st_ino == 0 else (info.st_dev, info.st_ino)


def _steps(base: Path, root: Path, rel: bytes) -> tuple[list[bytes], list[bytes]] | None:
    if root != base and base not in root.parents:
        return None
    down = [os.fsencode(part) for part in root.relative_to(base).parts]
    segments = [segment for segment in rel.split(b"/") if segment] if rel else []
    if any(part in _ODD or b"\\" in part for part in (*down, *segments)):
        return None
    return down, segments


def _by_path(
    base: Path,
    down: list[bytes],
    segments: list[bytes],
    *,
    keep_top: bool,
    identity: tuple[int, int] | None,
) -> RemoveFailure | None:
    here = base
    try:
        for part in down:
            here = here / os.fsdecode(part)
            if _is_link(here) or not here.is_dir():
                return RemoveFailure.NOT_CONTAINED
        if identity is None or _identity_of(os.stat(here, follow_symlinks=False)) != identity:
            return RemoveFailure.NOT_CONTAINED
        for segment in segments:
            here = here / os.fsdecode(segment)
            if not os.path.lexists(here):
                return None
            if _is_link(here):
                return RemoveFailure.REPARSE_POINT
            if not here.is_dir():
                return RemoveFailure.NOT_CONTAINED
        if _has_reparse_point(here):
            return RemoveFailure.REPARSE_POINT
        if keep_top:
            for child in list(here.iterdir()):
                if child.is_dir() and not _is_link(child):
                    shutil.rmtree(child, onexc=_gone_is_fine)
                else:
                    remove_file(child, missing_ok=True)
        else:
            shutil.rmtree(here, onexc=_gone_is_fine)
    except OSError:
        return RemoveFailure.OS_ERROR
    return None


def _open_down(current: int, parts: list[bytes], opened: list[int]) -> int:
    for part in parts:
        current = os.open(part, _DIR, dir_fd=current)
        opened.append(current)
    return current


def remove_under(
    base: Path,
    root: Path,
    rel: bytes,
    *,
    keep_top: bool,
    identity: tuple[int, int] | None,
) -> RemoveFailure | None:
    steps = _steps(base, root, rel)
    if steps is None:
        return RemoveFailure.NOT_CONTAINED
    down, segments = steps
    if not segments and not keep_top:
        return RemoveFailure.NOT_CONTAINED
    if not _fd_safe():
        return _by_path(base, down, segments, keep_top=keep_top, identity=identity)
    opened: list[int] = []
    try:
        try:
            current = os.open(base, _DIR)
            opened.append(current)
            current = _open_down(current, down, opened)
            if identity is None or _identity_of(os.fstat(current)) != identity:
                return RemoveFailure.NOT_CONTAINED
        except OSError as exc:
            if exc.errno in _NOT_FOLLOWED or isinstance(exc, FileNotFoundError):
                return RemoveFailure.NOT_CONTAINED
            return RemoveFailure.OS_ERROR
        walk = segments if keep_top else segments[:-1]
        for segment in walk:
            try:
                current = _open_down(current, [segment], opened)
            except FileNotFoundError:
                return None
            except OSError as exc:
                if exc.errno in _NOT_FOLLOWED:
                    return RemoveFailure.NOT_CONTAINED
                return RemoveFailure.OS_ERROR
        try:
            if keep_top:
                _empty(current)
            else:
                last = segments[-1]
                try:
                    info = os.stat(last, dir_fd=current, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                if not stat.S_ISDIR(info.st_mode):
                    return RemoveFailure.NOT_CONTAINED
                shutil.rmtree(last, dir_fd=current, onexc=_gone_is_fine)
        except OSError:
            return RemoveFailure.OS_ERROR
        return None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
