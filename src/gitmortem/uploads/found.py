import posixpath
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace

from gitmortem.db.models import UploadRepoRefusal
from gitmortem.scanning.imports import NAME_CHARS, plain_name
from gitmortem.uploads.ziplist import ZipEntry, ZipListing, ZipRefusal, ZipRefused

GIT = b".git"
MACOS_FORKS = b"__MACOSX"
_GIT_MEMBERS = frozenset({b"objects", b"refs", b"logs", b"worktrees"})
_ROOT_FILES = frozenset({b"HEAD", b"packed-refs"})
GIT_FILE_BYTES = 1024
_GITDIR = b"gitdir:"
MAX_REPOSITORIES = 10_000
_HEX = rb"[0-9a-f]"
LOOSE = re.compile(rb"objects/" + _HEX + rb"{2}/(?:" + _HEX + rb"{38}|" + _HEX + rb"{62})")
PACK = re.compile(
    rb"objects/pack/pack-(?:" + _HEX + rb"{40}|" + _HEX + rb"{64})\.(?:pack|promisor)"
)


def _ancestors(segments: Sequence[bytes]) -> Iterable[bytes]:
    for index in range(len(segments) + 1):
        yield b"/".join(segments[:index])


def _is_object(rest: Sequence[bytes]) -> bool:
    tail = b"/".join(rest)
    return bool(LOOSE.fullmatch(tail) or PACK.fullmatch(tail))


def is_git_entry(name: bytes) -> bool:
    segments = name.split(b"/")
    if segments[0] == MACOS_FORKS:
        return False
    if any(segment.lower() == GIT for segment in segments):
        return True
    if segments[-1] in _ROOT_FILES:
        return True
    return any(segment in _GIT_MEMBERS for segment in segments[:-1])


@dataclass(frozen=True)
class FoundRepo:
    zip_path: bytes
    git_prefix: bytes
    org: str | None
    name: str
    nested: tuple[bytes, ...] = ()
    shown_path: str = ""


@dataclass(frozen=True)
class RefusedRepo:
    zip_path: bytes
    refusal: UploadRepoRefusal


@dataclass(frozen=True)
class FoundRepos:
    repos: list[FoundRepo] = field(default_factory=list)
    refused: list[RefusedRepo] = field(default_factory=list)


def _join(segments: list[bytes]) -> bytes:
    return b"/".join(segments)


def _decode(raw: bytes, utf8: bool) -> str | None:
    try:
        return raw.decode("utf-8" if utf8 else "cp437")
    except UnicodeDecodeError:
        return None


def shown_path(raw: bytes, utf8: bool | None = None) -> str:
    if utf8 is not False:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            if utf8:
                return raw.decode("utf-8", "backslashreplace")
    return raw.decode("cp437")


def _resolved(work_tree: bytes, target: bytes) -> bytes | None:
    if not target or target.startswith(b"/") or b"\\" in target or target[1:2] == b":":
        return None
    joined = posixpath.normpath(posixpath.join(work_tree, target) if work_tree else target)
    if joined == b".." or joined.startswith(b"../"):
        return None
    return b"" if joined == b"." else joined


@dataclass
class _Marks:
    head: bool = False
    objects: bool = False
    utf8: bool = True


def find_repos(
    listing: ZipListing,
    read_small: Callable[[ZipEntry], bytes | None],
    *,
    client_name: str,
    org_prefix: str | None,
) -> FoundRepos:
    marks: dict[bytes, _Marks] = {}
    git_files: dict[bytes, ZipEntry] = {}
    ambiguous: set[bytes] = set()
    for entry in listing.entries:
        segments = entry.name.rstrip(b"/").split(b"/")
        if segments[0] == MACOS_FORKS:
            continue
        for index, segment in enumerate(segments):
            if segment.lower() == GIT and segment != GIT:
                ambiguous.add(_join(segments[:index]))
                break
        if segments[-1] == GIT and not entry.is_folder and entry.size <= GIT_FILE_BYTES:
            git_files[_join(segments[:-1])] = entry
            continue
        if entry.is_folder:
            continue
        if segments[-1] == b"HEAD":
            marks.setdefault(_join(segments[:-1]), _Marks()).head = True
        for index in range(max(0, len(segments) - 4), len(segments) - 1):
            if segments[index] == b"objects" and _is_object(segments[index:]):
                found = marks.setdefault(_join(segments[:index]), _Marks())
                found.objects = True
                found.utf8 = entry.utf8
                break
    git_dirs = {prefix for prefix, mark in marks.items() if mark.head and mark.objects}
    if len(git_dirs) > MAX_REPOSITORIES:
        raise ZipRefused(ZipRefusal.TOO_MANY_REPOSITORIES)

    def inside_ambiguous(path: bytes) -> bool:
        return bool(ambiguous) and any(
            ancestor in ambiguous for ancestor in _ancestors(path.split(b"/") if path else [])
        )

    def in_a_worktrees_folder(path: bytes) -> bool:
        segments = path.split(b"/")
        return any(
            segments[index] == b"worktrees" and _join(segments[:index]) in git_dirs
            for index in range(1, len(segments))
        )

    places: list[tuple[bytes, bytes, bool]] = []
    refused: list[RefusedRepo] = [
        RefusedRepo(folder, UploadRepoRefusal.AMBIGUOUS_CASE) for folder in sorted(ambiguous)
    ]
    for git_dir in sorted(git_dirs):
        if inside_ambiguous(git_dir):
            continue
        segments = git_dir.split(b"/") if git_dir else []
        if segments and segments[-1] == GIT:
            if GIT in segments[:-1]:
                continue
            places.append((_join(segments[:-1]), git_dir, False))
        elif GIT not in segments:
            places.append((git_dir, git_dir, True))
    claimed = {git_prefix: index for index, (_, git_prefix, _) in enumerate(places)}
    for work_tree, entry in sorted(git_files.items()):
        if inside_ambiguous(work_tree):
            continue
        content = read_small(entry)
        target = None
        if content is not None and content.startswith(_GITDIR):
            target = _resolved(work_tree, content[len(_GITDIR) :].strip())
        if target is None:
            refused.append(RefusedRepo(work_tree, UploadRepoRefusal.GIT_FILE_OUTSIDE))
        elif target in git_dirs:
            held = claimed.get(target)
            if held is None:
                claimed[target] = len(places)
                places.append((work_tree, target, False))
            elif places[held][2] and places[held][0] == target:
                places[held] = (work_tree, target, False)
        elif not in_a_worktrees_folder(target):
            refused.append(RefusedRepo(work_tree, UploadRepoRefusal.NOT_A_REPO))
    repos: list[FoundRepo] = []
    seen: set[tuple[str | None, str]] = set()
    stem = client_name[:-4] if client_name.lower().endswith(".zip") else client_name
    for zip_path, git_prefix, bare in sorted(places):
        parent, _, own = zip_path.rpartition(b"/")
        utf8 = marks[git_prefix].utf8
        name = stem if not zip_path else _decode(own, utf8)
        if name is not None and bare and zip_path and name.endswith(".git") and len(name) > 4:
            name = name[:-4]
        org = _decode(parent, utf8) if parent else None
        if org_prefix:
            org = org_prefix if org is None else f"{org_prefix}/{org}"
        try:
            if name is None or (parent and org is None):
                raise ValueError("not decodable")
            plain_name(name, NAME_CHARS)
            if org is not None:
                plain_name(org, NAME_CHARS)
        except ValueError:
            refused.append(RefusedRepo(zip_path, UploadRepoRefusal.BAD_ENTRY_NAME))
            continue
        if (org, name) in seen:
            refused.append(RefusedRepo(zip_path, UploadRepoRefusal.NAME_COLLISION))
            continue
        seen.add((org, name))
        repos.append(
            FoundRepo(zip_path, git_prefix, org, name, shown_path=shown_path(zip_path, utf8))
        )
    refused.sort(key=lambda r: r.zip_path)
    prefixes = {repo.git_prefix for repo in repos}
    nested: dict[bytes, list[bytes]] = {prefix: [] for prefix in prefixes}
    for prefix in sorted(prefixes):
        segments = prefix.split(b"/") if prefix else []
        for ancestor in _ancestors(segments[:-1]):
            if ancestor != prefix and ancestor in prefixes:
                nested[ancestor].append(prefix)
    repos = [replace(repo, nested=tuple(nested[repo.git_prefix])) for repo in repos]
    return FoundRepos(repos, refused)


def owned_entries(listing: ZipListing, repos: Sequence[FoundRepo]) -> dict[bytes, list[ZipEntry]]:
    owned: dict[bytes, list[ZipEntry]] = {repo.git_prefix: [] for repo in repos}
    for entry in listing.entries:
        if entry.is_folder:
            continue
        segments = entry.name.split(b"/")
        owner = None
        for ancestor in _ancestors(segments[:-1]):
            if ancestor in owned:
                owner = ancestor
        if owner is not None:
            owned[owner].append(entry)
    return owned
