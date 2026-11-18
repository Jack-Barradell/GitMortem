import errno
import os
import stat
import sys
import time
from collections.abc import Callable, Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from gitmortem.scanning.roots import (
    Reach,
    RootRefusal,
    RootRefused,
    SkippedFolders,
    contained_folder,
    containing_base,
    is_link,
    reach,
    resolved_bases,
    validate_root,
)

__all__ = [
    "LIST_SECONDS",
    "MAX_COUNTED",
    "MAX_FOLDERS",
    "MAX_READ",
    "MAX_REPOSITORIES",
    "Folder",
    "Listing",
    "RootState",
    "list_folders",
]

MAX_READ = 10_000
MAX_FOLDERS = 500
MAX_COUNTED = 2_000
MAX_REPOSITORIES = 100
LIST_SECONDS = 2.0

_FOLDER = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_BY_FOLDERS = (
    sys.platform != "win32"
    and os.open in os.supports_dir_fd
    and os.scandir in os.supports_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)
_UNREACHABLE = frozenset(
    {
        errno.ELOOP,
        errno.ENOENT,
        errno.ENOTDIR,
        errno.EACCES,
        errno.EPERM,
        getattr(errno, "EMLINK", errno.ELOOP),
    }
)

type _Held = int | Path


class RootState(StrEnum):
    NONE = "none"
    ROOT = "root"
    INSIDE_ROOT = "inside_root"
    HOLDS_ROOT = "holds_root"


@dataclass(frozen=True)
class Folder:
    name: str
    path: Path
    readable: bool
    is_repository: bool | None
    repositories: int | None
    repositories_more: bool
    root: RootState
    refusal: RootRefusal | None


@dataclass(frozen=True)
class Listing:
    path: Path | None
    base: Path | None
    parent: Path | None
    folders: list[Folder]
    truncated: bool
    partial: bool


def list_folders(
    text: str | None,
    *,
    bases: Collection[Path],
    data_dir: Path,
    key_file: Path | None,
    active: Collection[Path],
) -> Listing:
    if not bases:
        raise RootRefused(RootRefusal.NO_BASES)
    deadline = time.monotonic() + LIST_SECONDS
    judge = _Judge(bases=bases, data_dir=data_dir, key_file=key_file, active=active)
    if text is None:
        described = [
            judge.describe(base, str(base), _held_path(base), deadline)
            for base in resolved_bases(bases)
        ]
        return Listing(
            None,
            None,
            None,
            [folder for folder, _ in described],
            False,
            any(late for _, late in described),
        )
    found = contained_folder(text, bases=bases, data_dir=data_dir)
    if isinstance(found, RootRefusal):
        raise RootRefused(found)
    base = containing_base(found, bases)
    if base is None:
        raise RootRefused(RootRefusal.OUTSIDE_BASES)
    parent = None if found == base else found.parent
    above = reach(found)
    with _opened(found, base) as held:
        names, truncated = _subfolder_names(held, found, judge.skipped)
        folders: list[Folder] = []
        partial = False
        for name in names:
            folder, late = judge.describe(
                found / name, name, _child(held, name), deadline, above=above
            )
            folders.append(folder)
            partial = partial or late
    return Listing(found, base, parent, folders, truncated, partial)


class _Judge:
    def __init__(
        self,
        *,
        bases: Collection[Path],
        data_dir: Path,
        key_file: Path | None,
        active: Collection[Path],
    ) -> None:
        self.bases = bases
        self.data_dir = data_dir
        self.key_file = key_file
        self.roots = [reach(root) for root in active]
        self.skipped = SkippedFolders([data_dir])

    def describe(
        self,
        path: Path,
        name: str,
        held: "_Opener",
        deadline: float,
        *,
        above: Reach | None = None,
    ) -> tuple[Folder, bool]:
        late = time.monotonic() > deadline
        readable, is_repository, repositories, more = (
            (True, None, None, False) if late else held.count()
        )
        root = self._root_state(reach(path, above=above))
        try:
            validate_root(
                str(path),
                bases=self.bases,
                data_dir=self.data_dir,
                key_file=self.key_file,
                active=(),
            )
            refusal = None if root is RootState.NONE else RootRefusal.OVERLAPS_ROOT
        except RootRefused as refused:
            refusal = refused.reason
        if late:
            readable = held.readable()
        folder = Folder(
            name=name,
            path=path,
            readable=readable,
            is_repository=is_repository,
            repositories=repositories,
            repositories_more=more,
            root=root,
            refusal=refusal,
        )
        return folder, late

    def _root_state(self, here: Reach) -> RootState:
        inside = [here.within(root) for root in self.roots]
        holds = [root.within(here) for root in self.roots]
        if any(i and h for i, h in zip(inside, holds, strict=True)):
            return RootState.ROOT
        if any(inside):
            return RootState.INSIDE_ROOT
        if any(holds):
            return RootState.HOLDS_ROOT
        return RootState.NONE


@contextmanager
def _opened(folder: Path, base: Path) -> Iterator[_Held]:
    if not _BY_FOLDERS:
        try:
            checked = _checked_path(folder)
        except OSError as error:
            _refuse_if_unreachable(error)
            raise
        yield checked
        return
    try:
        held = os.open(base, _FOLDER)
        try:
            for name in folder.relative_to(base).parts:
                inner = os.open(name, _FOLDER, dir_fd=held)
                os.close(held)
                held = inner
        except BaseException:
            os.close(held)
            raise
    except OSError as error:
        _refuse_if_unreachable(error)
        raise
    try:
        yield held
    finally:
        os.close(held)


def _refuse_if_unreachable(error: OSError) -> None:
    if error.errno in _UNREACHABLE:
        raise RootRefused(RootRefusal.MISSING) from None


def _subfolder_names(held: _Held, folder: Path, skipped: SkippedFolders) -> tuple[list[str], bool]:
    found: list[str] = []
    cut = False
    try:
        listed = os.scandir(held)
    except OSError as error:
        _refuse_if_unreachable(error)
        raise
    with listed as entries:
        for read, entry in enumerate(entries, start=1):
            if read > MAX_READ:
                cut = True
                break
            try:
                if is_link(entry) or not entry.is_dir(follow_symlinks=False):
                    continue
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not _is_utf8(entry.name):
                continue
            ident = None if info.st_ino == 0 else (info.st_dev, info.st_ino)
            if skipped.is_skipped(folder / entry.name, ident):
                continue
            found.append(entry.name)
    found.sort()
    return found[:MAX_FOLDERS], cut or len(found) > MAX_FOLDERS


def _is_utf8(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


class _Opener:
    def __init__(self, open_it: Callable[[], _Held], close_it: Callable[[_Held], None]) -> None:
        self.open = open_it
        self.close = close_it

    def readable(self) -> bool:
        try:
            held = self.open()
        except OSError:
            return False
        self.close(held)
        return True

    def count(self) -> tuple[bool, bool | None, int | None, bool]:
        try:
            held = self.open()
        except OSError:
            return False, None, None, False
        try:
            itself = _is_repository(held)
            repositories, more = _repositories_in(held)
        except OSError:
            return False, None, None, False
        finally:
            self.close(held)
        return True, itself, repositories, more


def _held_path(path: Path) -> _Opener:
    if _BY_FOLDERS:
        return _Opener(lambda: os.open(path, _FOLDER), _release)
    return _Opener(lambda: _checked_path(path), _release)


def _child(held: _Held, name: str) -> _Opener:
    if isinstance(held, int):
        return _Opener(lambda: os.open(name, _FOLDER, dir_fd=held), _release)
    return _Opener(lambda: _checked_path(held / name), _release)


def _release(held: _Held) -> None:
    if isinstance(held, int):
        os.close(held)


def _checked_path(path: Path) -> Path:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, "not a folder", str(path))
    return path


def _lstat(held: _Held, name: str) -> os.stat_result | None:
    try:
        if isinstance(held, int):
            return os.stat(name, dir_fd=held, follow_symlinks=False)
        return os.lstat(held / name)
    except OSError:
        return None


def _is_repository(held: _Held) -> bool:
    git = _lstat(held, ".git")
    if git is not None and (stat.S_ISDIR(git.st_mode) or stat.S_ISREG(git.st_mode)):
        return True
    head, objects, refs = (_lstat(held, name) for name in ("HEAD", "objects", "refs"))
    return (
        head is not None
        and stat.S_ISREG(head.st_mode)
        and objects is not None
        and stat.S_ISDIR(objects.st_mode)
        and refs is not None
        and stat.S_ISDIR(refs.st_mode)
    )


def _repositories_in(held: _Held) -> tuple[int, bool]:
    count = 0
    with os.scandir(held) as entries:
        for read, entry in enumerate(entries, start=1):
            if read > MAX_COUNTED:
                return count, True
            try:
                if (
                    entry.name == ".git"
                    or is_link(entry)
                    or not entry.is_dir(follow_symlinks=False)
                ):
                    continue
            except OSError:
                continue
            opener = _child(held, entry.name)
            try:
                inner = opener.open()
            except OSError:
                continue
            try:
                found = _is_repository(inner)
            finally:
                opener.close(inner)
            if not found:
                continue
            if count == MAX_REPOSITORIES:
                return count, True
            count += 1
    return count, False
