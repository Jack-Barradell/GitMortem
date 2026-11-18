import os
import re
import stat
import sys
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath

MAX_LINK_HOPS = 40
_ON_WINDOWS = sys.platform == "win32"
_DRIVE = re.compile(r"^[A-Za-z]:$")


class RootRefusal(StrEnum):
    NOT_ABSOLUTE = "not_absolute"
    MISSING = "missing"
    NOT_A_DIRECTORY = "not_a_directory"
    OUTSIDE_BASES = "outside_bases"
    INSIDE_DATA_DIR = "inside_data_dir"
    HOLDS_KEY_FILE = "holds_key_file"
    OVERLAPS_ROOT = "overlaps_root"
    NO_BASES = "no_bases"
    NOT_UTF8 = "not_utf8"


MESSAGES: dict[RootRefusal, str] = {
    RootRefusal.NOT_ABSOLUTE: "A scan root must be an absolute path.",
    RootRefusal.MISSING: "No such folder, or it cannot be read.",
    RootRefusal.NOT_A_DIRECTORY: "That path is not a folder.",
    RootRefusal.OUTSIDE_BASES: "That folder is not inside a base the operator allowed.",
    RootRefusal.INSIDE_DATA_DIR: "A scan root cannot be inside GitMortem's own data folder.",
    RootRefusal.HOLDS_KEY_FILE: "A scan root cannot contain the instance key file.",
    RootRefusal.OVERLAPS_ROOT: "That folder is inside, or contains, a scan root already added.",
    RootRefusal.NO_BASES: (
        "The operator has named no scan root bases. Restart with --scan-root-base."
    ),
    RootRefusal.NOT_UTF8: "A scan root must be valid text (UTF-8).",
}


class RootRefused(Exception):
    def __init__(self, reason: RootRefusal) -> None:
        super().__init__(MESSAGES[reason])
        self.reason = reason


def spelled_within(path: Path, ancestor: Path) -> bool:
    return path == ancestor or ancestor in path.parents


def same_folder_within(path: Path, ancestor: Path) -> bool:
    try:
        wanted = os.stat(ancestor)
    except OSError:
        return False
    if wanted.st_ino == 0:
        return False
    for candidate in (path, *path.parents):
        try:
            found = os.stat(candidate)
        except OSError:
            continue
        if found.st_ino != 0 and os.path.samestat(found, wanted):
            return True
    return False


def is_within(path: Path, ancestor: Path) -> bool:
    return spelled_within(path, ancestor) or same_folder_within(path, ancestor)


Identity = tuple[int, int]


def is_link(entry: "os.DirEntry[str] | os.DirEntry[bytes]") -> bool:
    return entry.is_symlink() or entry.is_junction()


def folder_identity(path: bytes) -> Identity | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return None if info.st_ino == 0 else (info.st_dev, info.st_ino)


@dataclass(frozen=True)
class Reach:
    path: Path
    identity: Identity | None
    spellings: frozenset[Path]
    identities: frozenset[Identity]

    def within(self, ancestor: "Reach") -> bool:
        return ancestor.path in self.spellings or (
            ancestor.identity is not None and ancestor.identity in self.identities
        )


def _identity(path: Path) -> Identity | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return None if info.st_ino == 0 else (info.st_dev, info.st_ino)


def reach(path: Path, *, above: Reach | None = None) -> Reach:
    own = _identity(path)
    if above is None:
        parents = [(parent, _identity(parent)) for parent in path.parents]
        spellings = frozenset([path, *(parent for parent, _ in parents)])
        found = [ident for _, ident in parents]
    else:
        if path.parent != above.path:
            raise ValueError("a reach is read down from its parent's alone")
        spellings = above.spellings | {path}
        found = list(above.identities)
    identities = frozenset(ident for ident in (own, *found) if ident is not None)
    return Reach(path, own, spellings, identities)


class SkippedFolders:
    def __init__(self, folders: Collection[Path]) -> None:
        self.paths = [folder.resolve() for folder in folders]
        self.identities = {
            ident
            for path in self.paths
            if (ident := folder_identity(os.fsencode(path))) is not None
        }

    def is_skipped(self, path: Path, ident: Identity | None) -> bool:
        return path in self.paths or (ident is not None and ident in self.identities)

    def covers(self, path: Path) -> bool:
        return any(is_within(path, folder) for folder in self.paths)


def _resolve_dir(path: Path | str) -> Path | None:
    try:
        resolved = Path(path).resolve(strict=True)
        return resolved if resolved.is_dir() else None
    except (OSError, RuntimeError, ValueError):
        return None


def _resolved_bases(bases: Collection[Path]) -> list[Path]:
    return [r for b in bases if (r := _resolve_dir(b)) is not None]


def _base_holds(path: Path, base: Path) -> bool:
    if not spelled_within(path, base):
        return False
    return not _ON_WINDOWS or same_folder_within(path, base)


def _inside_bases(path: Path, bases: Collection[Path]) -> bool:
    return any(_base_holds(path, base) for base in _resolved_bases(bases))


def containing_base(path: Path, bases: Collection[Path]) -> Path | None:
    inside = [base for base in _resolved_bases(bases) if _base_holds(path, base)]
    return min(inside, key=lambda base: len(base.parts), default=None)


def names_a_remote_path(text: str, *, windows: bool = _ON_WINDOWS) -> bool:
    if not windows:
        return False
    if text[:2].replace("/", "\\") == "\\\\":
        return True
    return not _DRIVE.match(PureWindowsPath(text).drive)


def _is_link_at(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse = getattr(info, "st_reparse_tag", 0)
    return bool(reparse) and path.is_junction()


def real_inside(path: Path, root: Path) -> Path | None:
    spelled = Path(os.path.normpath(path))
    if not spelled_within(spelled, root):
        return None
    queue = list(spelled.relative_to(root).parts)
    current = root
    hops = 0
    while queue:
        part = queue.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            if not spelled_within(current, root):
                return None
            continue
        step = current / part
        try:
            info = os.lstat(step)
        except (FileNotFoundError, NotADirectoryError):
            return step.joinpath(*queue)
        if not _is_link_at(step, info):
            current = step
            continue
        hops += 1
        if hops > MAX_LINK_HOPS:
            return None
        named = os.readlink(step)
        target = Path(os.path.normpath(named if os.path.isabs(named) else current / named))
        if names_a_remote_path(str(target)) or not spelled_within(target, root):
            return None
        queue = [*target.relative_to(root).parts, *queue]
        current = root
    return current


def _containment_refusal(
    root: Path, *, bases: Collection[Path], data_dir: Path, key_file: Path | None
) -> RootRefusal | None:
    if not _inside_bases(root, bases):
        return RootRefusal.OUTSIDE_BASES
    if not _is_utf8(str(root)):
        return RootRefusal.NOT_UTF8
    if is_within(root, data_dir.resolve()):
        return RootRefusal.INSIDE_DATA_DIR
    if key_file is not None and is_within(key_file.resolve(), root):
        return RootRefusal.HOLDS_KEY_FILE
    return None


def validate_root(
    text: str,
    *,
    bases: Collection[Path],
    data_dir: Path,
    key_file: Path | None,
    active: Collection[Path],
) -> Path:
    if not bases:
        raise RootRefused(RootRefusal.NO_BASES)
    if not _is_utf8(text):
        raise RootRefused(RootRefusal.NOT_UTF8)
    if names_a_remote_path(text):
        raise RootRefused(RootRefusal.OUTSIDE_BASES)
    typed = Path(text)
    if not typed.is_absolute():
        raise RootRefused(RootRefusal.NOT_ABSOLUTE)
    try:
        root = typed.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise RootRefused(_unresolved_refusal(typed, bases)) from None
    if not _inside_bases(root, bases):
        raise RootRefused(RootRefusal.OUTSIDE_BASES)
    if not root.is_dir():
        raise RootRefused(RootRefusal.NOT_A_DIRECTORY)
    refusal = _containment_refusal(root, bases=bases, data_dir=data_dir, key_file=key_file)
    if refusal is not None:
        raise RootRefused(refusal)
    if any(is_within(root, other) or is_within(other, root) for other in active):
        raise RootRefused(RootRefusal.OVERLAPS_ROOT)
    return root


def _unresolved_refusal(typed: Path, bases: Collection[Path]) -> RootRefusal:
    try:
        reached = Path(os.path.realpath(typed))
    except (OSError, ValueError):
        reached = Path(os.path.normpath(typed))
    return RootRefusal.MISSING if _inside_bases(reached, bases) else RootRefusal.OUTSIDE_BASES


def contained_file(
    text: str, *, bases: Collection[Path], data_dir: Path, key_file: Path | None
) -> Path | RootRefusal:
    if not bases:
        return RootRefusal.NO_BASES
    if not _is_utf8(text):
        return RootRefusal.NOT_UTF8
    if names_a_remote_path(text):
        return RootRefusal.OUTSIDE_BASES
    typed = Path(text)
    if not typed.is_absolute():
        return RootRefusal.NOT_ABSOLUTE
    try:
        resolved = typed.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return _unresolved_refusal(typed, bases)
    refusal = _containment_refusal(resolved, bases=bases, data_dir=data_dir, key_file=key_file)
    return resolved if refusal is None else refusal


def contained_folder(text: str, *, bases: Collection[Path], data_dir: Path) -> Path | RootRefusal:
    if not bases:
        return RootRefusal.NO_BASES
    if not _is_utf8(text):
        return RootRefusal.NOT_UTF8
    if names_a_remote_path(text):
        return RootRefusal.OUTSIDE_BASES
    typed = Path(text)
    if not typed.is_absolute():
        return RootRefusal.NOT_ABSOLUTE
    try:
        folder = typed.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return _unresolved_refusal(typed, bases)
    if not _inside_bases(folder, bases):
        return RootRefusal.OUTSIDE_BASES
    if not folder.is_dir():
        return RootRefusal.NOT_A_DIRECTORY
    if not _is_utf8(str(folder)):
        return RootRefusal.NOT_UTF8
    if is_within(folder, data_dir.resolve()):
        return RootRefusal.INSIDE_DATA_DIR
    return folder


def resolved_bases(bases: Collection[Path]) -> list[Path]:
    return _resolved_bases(bases)


def root_is_usable(
    root: Path | str, *, bases: Collection[Path], data_dir: Path, key_file: Path | None
) -> bool:
    resolved = _resolve_dir(root)
    if resolved is None:
        return False
    return _containment_refusal(resolved, bases=bases, data_dir=data_dir, key_file=key_file) is None


def _is_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
