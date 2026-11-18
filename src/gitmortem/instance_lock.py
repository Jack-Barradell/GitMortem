import errno
import importlib
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_NAME = "gitmortem.lock"
_OPEN_FLAGS = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
_WINDOWS_HELD = frozenset({errno.EACCES, getattr(errno, "EDEADLOCK", errno.EDEADLK)})


class InstanceLocked(Exception):
    def __init__(self, data_dir: Path) -> None:
        super().__init__(f"another GitMortem is already using {data_dir}")
        self.data_dir = data_dir


def _lock(fd: int, *, posix: bool) -> bool:
    if sys.platform != "win32" and posix:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    msvcrt = importlib.import_module("msvcrt")
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        if exc.errno in _WINDOWS_HELD:
            return False
        raise
    return True


def _unlock(fd: int, *, posix: bool) -> None:
    if sys.platform != "win32" and posix:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    msvcrt = importlib.import_module("msvcrt")
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def hold(data_dir: Path, *, posix: bool | None = None) -> Iterator[None]:
    if posix is None:
        posix = os.name == "posix"
    fd = os.open(data_dir / LOCK_NAME, _OPEN_FLAGS, 0o600)
    try:
        if not _lock(fd, posix=posix):
            raise InstanceLocked(data_dir)
        try:
            yield
        finally:
            _unlock(fd, posix=posix)
    finally:
        os.close(fd)
