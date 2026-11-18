import os
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path

__all__ = ["remove_file", "remove_tree", "writable_again"]


def writable_again(function: Callable[..., object], path: str | bytes, exc: BaseException) -> None:
    if sys.platform == "win32" and isinstance(exc, PermissionError):
        attributes = os.lstat(path).st_file_attributes
        read_only = attributes & stat.FILE_ATTRIBUTE_READONLY
        if read_only and not attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            os.chmod(path, stat.S_IWRITE)
            function(path)
            return
    raise exc


def remove_tree(path: Path, *, missing_ok: bool = False, ignore_errors: bool = False) -> None:
    def refused(function: Callable[..., object], name: str | bytes, exc: BaseException) -> None:
        if (missing_ok or ignore_errors) and isinstance(exc, FileNotFoundError):
            return
        try:
            writable_again(function, name, exc)
        except OSError:
            if not ignore_errors:
                raise

    shutil.rmtree(path, onexc=refused)


def remove_file(path: Path, *, missing_ok: bool = False) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        if not missing_ok:
            raise
    except PermissionError as error:
        writable_again(os.unlink, str(path), error)
