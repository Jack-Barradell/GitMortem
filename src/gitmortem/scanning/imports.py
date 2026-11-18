import errno
import hashlib
import hmac
import json
import math
import os
import stat
import sys
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from sqlalchemy import BindParameter, and_, bindparam, delete, func, or_, select, update
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.config import Settings, guarded_key_file
from gitmortem.crypto import RawStore
from gitmortem.db.models import (
    DeletionState,
    Finding,
    Import,
    ImportFailure,
    ImportSource,
    ImportState,
    IntegrityState,
    MetaFrom,
    Note,
    Repository,
    RepositoryKind,
    RepositoryState,
    Role,
    Scan,
    ScanKind,
    ScanState,
    Secret,
    Sighting,
    StatusChange,
    ToolName,
    ToolRun,
    ToolRunState,
    User,
)
from gitmortem.scanning import gitleaks
from gitmortem.scanning.current import UNFINISHED_RUN
from gitmortem.scanning.roots import (
    Identity,
    RootRefusal,
    contained_file,
    containing_base,
    folder_identity,
)
from gitmortem.scanning.settings import (
    IMPORT_BYTES_CEILING,
    get_scan_workers,
    get_tool_settings,
    get_upload_limits,
)
from gitmortem.scanning.store import recompute_imported_kinds
from gitmortem.scanning.streams import REFUSALS
from gitmortem.scanning.tools import UPLOAD_PART
from gitmortem.triage.subjects import Subject, SubjectKind

__all__ = [
    "CHECKED_EXPIRES",
    "CHECK_COUNTS",
    "EXPIRY_SECONDS",
    "IMPORTABLE",
    "JOB_STATES",
    "MAX_IMPORT_BYTES",
    "MAX_PIECE_BYTES",
    "NOT_STORED",
    "UNREADABLE_REASONS",
    "UPLOAD_EXPIRES",
    "ImportFailure",
    "ImportRefusal",
    "ImportRefused",
    "ImportSource",
    "ImportState",
    "ImportTarget",
    "NotOnDisk",
    "RemovalCounts",
    "RepositoryId",
    "add_piece",
    "check_server_file",
    "confirm",
    "create_upload",
    "discard",
    "expire_imports",
    "expires_at",
    "finish_upload",
    "from_server_file",
    "open_server_file",
    "own_run",
    "own_scan",
    "plain_name",
    "removable",
    "removal_counts",
    "remove",
]

MAX_IMPORT_BYTES = IMPORT_BYTES_CEILING
MAX_PIECE_BYTES = 256 << 10
UPLOAD_EXPIRES = timedelta(hours=24)
CHECKED_EXPIRES = timedelta(days=7)
EXPIRY_SECONDS = 3600.0
NAME_CHARS = 100
CLIENT_NAME_CHARS = 255
SERVER_PATH_CHARS = 4096
IMPORTABLE: Mapping[ToolName, str] = {
    ToolName.GIT_SECRETS: "stderr",
    ToolName.GITLEAKS: gitleaks.REPORT,
    ToolName.TRUFFLEHOG: "stdout",
}
CHECK_COUNTS = (
    "records",
    "values",
    "standalone",
    "redacted",
    "unknown_commits",
    "parse_issues",
    "reported_live",
)
PIECE_UNREADABLE = "a sealed piece of the report could not be opened"
FILE_CHANGED = "the file changed, or could no longer be read, while it was read"
NOT_STORED = "the file could not be stored: the disk may be full"
UNREADABLE_REASONS = REFUSALS | {PIECE_UNREADABLE, FILE_CHANGED, NOT_STORED}
_OPEN_FILE = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_OPEN_FILE |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOCTTY", 0)
_FOLDER = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_BY_FOLDERS = (
    os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
)
_MOVED = frozenset(
    {errno.ELOOP, errno.ENOENT, errno.ENOTDIR, getattr(errno, "EMLINK", errno.ELOOP)}
)
JOB_STATES = (ImportState.CHECKING, ImportState.RECORDING)
_ENDED = (ImportState.DISCARDED, ImportState.REMOVED)
_CHUNK = 10_000


class ImportRefusal(StrEnum):
    EMPTY = "empty"
    TOO_LARGE = "too_large"
    NOT_IMPORTABLE = "not_importable"
    NO_SUCH_REPOSITORY = "no_such_repository"
    NEEDS_REPOSITORY_ON_DISK = "needs_repository_on_disk"
    BAD_NAME = "bad_name"
    NO_SUCH_IMPORT = "no_such_import"
    NOT_AN_UPLOAD = "not_an_upload"
    NOT_UPLOADING = "not_uploading"
    OUT_OF_ORDER = "out_of_order"
    BAD_PIECE = "bad_piece"
    INCOMPLETE = "incomplete"
    NOT_CHECKED = "not_checked"
    CONFIRMED = "confirmed"
    RECORDED = "recorded"
    NOT_RECORDED = "not_recorded"
    BUSY = "busy"
    ENDED = "ended"
    NO_BASES = "no_bases"
    NOT_ABSOLUTE = "not_absolute"
    OUTSIDE_BASES = "outside_bases"
    NOT_UTF8 = "not_utf8"
    OWN_FILE = "own_file"
    PATH_TOO_LONG = "path_too_long"
    MISSING = "missing"
    NOT_A_FILE = "not_a_file"
    UNREADABLE_FILE = "unreadable_file"
    CHANGED = "changed"
    AMBIGUOUS_REPOSITORY = "ambiguous_repository"
    NOT_YOURS = "not_yours"
    REMOVAL_CHANGED = "removal_changed"
    REPOSITORY_BEING_DELETED = "repository_being_deleted"


REFUSALS_TEXT: Mapping[ImportRefusal, str] = {
    ImportRefusal.EMPTY: "An import holds at least one byte.",
    ImportRefusal.TOO_LARGE: (
        f"An import is at most {MAX_IMPORT_BYTES >> 20} MiB, or the lower limit an admin set."
    ),
    ImportRefusal.NOT_IMPORTABLE: "GitMortem imports git-secrets, gitleaks and TruffleHog output.",
    ImportRefusal.NO_SUCH_REPOSITORY: "No such repository.",
    ImportRefusal.AMBIGUOUS_REPOSITORY: (
        "More than one uploaded repository has that org and name: choose the repository instead."
    ),
    ImportRefusal.NOT_YOURS: "Only the user who started this import, or an admin, may do that.",
    ImportRefusal.REPOSITORY_BEING_DELETED: (
        "That repository is being deleted, or its deletion failed: import against it once that"
        " is settled."
    ),
    ImportRefusal.REMOVAL_CHANGED: (
        "What removing this import would delete has changed since its counts were read: read"
        " them again."
    ),
    ImportRefusal.NEEDS_REPOSITORY_ON_DISK: (
        "git-secrets output can only be imported against a repository on disk: its paths are "
        "settled against the repository's own history."
    ),
    ImportRefusal.BAD_NAME: (
        "A name is 1 to its bound in characters, none of them a control or format character."
    ),
    ImportRefusal.NO_SUCH_IMPORT: "No such import.",
    ImportRefusal.NOT_AN_UPLOAD: "That import reads a file on the server: it takes no pieces.",
    ImportRefusal.NOT_UPLOADING: "That import's upload has already been finished.",
    ImportRefusal.OUT_OF_ORDER: "Pieces arrive in order, each once, and no more than planned.",
    ImportRefusal.BAD_PIECE: (
        f"Each piece is {MAX_PIECE_BYTES >> 10} KiB, the last what is left of the planned size."
    ),
    ImportRefusal.INCOMPLETE: "Not every piece has arrived yet.",
    ImportRefusal.NOT_CHECKED: "Only an import whose check has ended can be confirmed.",
    ImportRefusal.CONFIRMED: "That import has already been confirmed.",
    ImportRefusal.RECORDED: "A recorded import is removed, not discarded.",
    ImportRefusal.NOT_RECORDED: (
        "That import recorded nothing, so there is nothing to remove: an upload or a checked "
        "import is discarded instead."
    ),
    ImportRefusal.BUSY: (
        "The import's check or record, or a re-read of it, is still under way: try again once it "
        "has ended."
    ),
    ImportRefusal.ENDED: "That import has ended.",
    ImportRefusal.NO_BASES: (
        "The operator has named no scan root bases. Restart with --scan-root-base."
    ),
    ImportRefusal.NOT_ABSOLUTE: "A file on the server is named by its absolute path.",
    ImportRefusal.OUTSIDE_BASES: "That file is not inside a base the operator allowed.",
    ImportRefusal.NOT_UTF8: "A path must be valid text (UTF-8).",
    ImportRefusal.OWN_FILE: "GitMortem never reads its own data folder or key file.",
    ImportRefusal.PATH_TOO_LONG: f"A path is at most {SERVER_PATH_CHARS:,} characters.",
    ImportRefusal.MISSING: "No such file, or it cannot be read.",
    ImportRefusal.NOT_A_FILE: "That is not a regular file.",
    ImportRefusal.UNREADABLE_FILE: "That file could not be read.",
    ImportRefusal.CHANGED: (
        "That file, or a folder on its way, changed while it was checked: name it again."
    ),
}
_FROM_ROOT: Mapping[RootRefusal, ImportRefusal] = {
    RootRefusal.NO_BASES: ImportRefusal.NO_BASES,
    RootRefusal.NOT_ABSOLUTE: ImportRefusal.NOT_ABSOLUTE,
    RootRefusal.MISSING: ImportRefusal.MISSING,
    RootRefusal.OUTSIDE_BASES: ImportRefusal.OUTSIDE_BASES,
    RootRefusal.NOT_UTF8: ImportRefusal.NOT_UTF8,
    RootRefusal.INSIDE_DATA_DIR: ImportRefusal.OWN_FILE,
    RootRefusal.HOLDS_KEY_FILE: ImportRefusal.OWN_FILE,
}


class ImportRefused(Exception):
    def __init__(self, reason: ImportRefusal) -> None:
        super().__init__(REFUSALS_TEXT[reason])
        self.reason = reason


def plain_name(text: str, limit: int) -> str:
    plain = 1 <= len(text) <= limit and not any(
        unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in text
    )
    if not plain:
        raise ValueError(
            f"names are each 1 to {limit} characters, none a control or format character"
        )
    return text


@dataclass(frozen=True)
class RepositoryId:
    id: int


@dataclass(frozen=True)
class NotOnDisk:
    org: str
    name: str

    def __post_init__(self) -> None:
        plain_name(self.org, NAME_CHARS)
        plain_name(self.name, NAME_CHARS)


ImportTarget = RepositoryId | NotOnDisk


@dataclass(frozen=True)
class RemovalCounts:
    findings: int
    secrets: int
    with_triage: int
    digest: str = field(default="", compare=False)


def _import(session: Session, import_id: int) -> Import:
    found = session.get(Import, import_id)
    if found is None:
        raise ImportRefused(ImportRefusal.NO_SUCH_IMPORT)
    return found


def own_run(session: Session, imported: Import) -> ToolRun:
    return session.scalars(
        select(ToolRun).where(ToolRun.scan_id == imported.scan_id, ToolRun.reread_of_id.is_(None))
    ).one()


def own_scan(session: Session, imported: Import) -> Scan:
    return session.scalars(select(Scan).where(Scan.id == imported.scan_id)).one()


def _repository(
    session: Session, tool: ToolName, target: ImportTarget, now: datetime
) -> Repository:
    if isinstance(target, RepositoryId):
        found = session.get(Repository, target.id)
        if found is None or found.deletion_state is DeletionState.DELETED:
            raise ImportRefused(ImportRefusal.NO_SUCH_REPOSITORY)
        if found.deletion_state is not None:
            raise ImportRefused(ImportRefusal.REPOSITORY_BEING_DELETED)
        if tool is ToolName.GIT_SECRETS and found.kind is RepositoryKind.NOT_ON_DISK:
            raise ImportRefused(ImportRefusal.NEEDS_REPOSITORY_ON_DISK)
        return found
    uploaded = session.scalars(
        select(Repository).where(
            Repository.kind == RepositoryKind.UPLOADED,
            Repository.org == target.org,
            Repository.name == target.name,
            Repository.deletion_state.is_(None),
        )
    ).all()
    if len(uploaded) > 1:
        raise ImportRefused(ImportRefusal.AMBIGUOUS_REPOSITORY)
    if uploaded:
        return uploaded[0]
    if tool is ToolName.GIT_SECRETS:
        raise ImportRefused(ImportRefusal.NEEDS_REPOSITORY_ON_DISK)
    found = session.scalars(
        select(Repository).where(
            Repository.kind == RepositoryKind.NOT_ON_DISK,
            Repository.org == target.org,
            Repository.name == target.name,
        )
    ).one_or_none()
    if found is not None and found.deletion_state is DeletionState.DELETED:
        found.deletion_state = None
        found.deletion_failure = None
        found.deletion_id = None
        found.deleted_at = None
        found.first_seen_at = now
        found.last_seen_at = now
        session.flush()
        return found
    if found is not None and found.deletion_state is not None:
        raise ImportRefused(ImportRefusal.REPOSITORY_BEING_DELETED)
    if found is not None:
        return found
    made = Repository(
        kind=RepositoryKind.NOT_ON_DISK,
        org=target.org,
        name=target.name,
        display_path=f"{target.org}/{target.name}",
        state=RepositoryState.MISSING,
        size_bytes=0,
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(made)
    session.flush()
    return made


def _bounded_size(size_bytes: int, limit: int = MAX_IMPORT_BYTES) -> None:
    if size_bytes < 1:
        raise ImportRefused(ImportRefusal.EMPTY)
    if size_bytes > min(limit, MAX_IMPORT_BYTES):
        raise ImportRefused(ImportRefusal.TOO_LARGE)


def _made(
    session: Session,
    user: User | None,
    *,
    tool: ToolName,
    target: ImportTarget,
    source: ImportSource,
    state: ImportState,
    size_bytes: int,
    client_name: str | None,
    server_path: str | None,
    now: datetime,
) -> Import:
    if tool not in IMPORTABLE:
        raise ImportRefused(ImportRefusal.NOT_IMPORTABLE)
    _bounded_size(size_bytes, get_upload_limits(session).import_bytes)
    if client_name is not None:
        try:
            plain_name(client_name, CLIENT_NAME_CHARS)
        except ValueError:
            raise ImportRefused(ImportRefusal.BAD_NAME) from None
    repository = _repository(session, tool, target, now)
    scan = Scan(
        state=ScanState.QUEUED,
        kind=ScanKind.IMPORT,
        workers=get_scan_workers(session),
        started_by_user_id=None if user is None else user.id,
        created_at=now,
    )
    session.add(scan)
    session.flush()
    session.add(
        ToolRun(
            scan_id=scan.id,
            repository_id=repository.id,
            tool=tool,
            identity=f"imported {tool.value} output",
            state=ToolRunState.QUEUED,
            integrity=IntegrityState.NOT_CHECKED,
            timeout_seconds=get_tool_settings(session, tool).timeout_seconds,
        )
    )
    made = Import(
        scan_id=scan.id,
        tool=tool,
        repository_id=repository.id,
        state=state,
        source=source,
        client_name=client_name,
        server_path=server_path,
        size_bytes=size_bytes,
        pieces=math.ceil(size_bytes / MAX_PIECE_BYTES),
        pieces_received=0,
        created_by_user_id=None if user is None else user.id,
        created_at=now,
        updated_at=now,
    )
    session.add(made)
    session.flush()
    return made


def create_upload(
    session: Session,
    user: User | None,
    *,
    tool: ToolName,
    target: ImportTarget,
    client_name: str | None,
    size_bytes: int,
    now: datetime,
) -> Import:
    return _made(
        session,
        user,
        tool=tool,
        target=target,
        source=ImportSource.UPLOAD,
        state=ImportState.UPLOADING,
        size_bytes=size_bytes,
        client_name=client_name,
        server_path=None,
        now=now,
    )


def _refuse_ended(imported: Import) -> None:
    if imported.state in _ENDED or imported.state is ImportState.FAILED:
        raise ImportRefused(ImportRefusal.ENDED)


def _owned(imported: Import, user: User | None, *, admin_too: bool) -> None:
    if user is not None and admin_too and user.role is Role.ADMIN:
        return
    if user is None or imported.created_by_user_id != user.id:
        raise ImportRefused(ImportRefusal.NOT_YOURS)


def _uploading(session: Session, import_id: int, user: User | None) -> Import:
    imported = _import(session, import_id)
    _owned(imported, user, admin_too=False)
    if imported.source is not ImportSource.UPLOAD:
        raise ImportRefused(ImportRefusal.NOT_AN_UPLOAD)
    _refuse_ended(imported)
    if imported.state is not ImportState.UPLOADING:
        raise ImportRefused(ImportRefusal.NOT_UPLOADING)
    return imported


def _piece_size(imported: Import, seq: int) -> int:
    if seq < imported.pieces:
        return MAX_PIECE_BYTES
    return imported.size_bytes - (imported.pieces - 1) * MAX_PIECE_BYTES


def add_piece(
    session: Session,
    import_id: int,
    seq: int,
    data: bytes,
    *,
    user: User | None,
    raw_store: RawStore,
    now: datetime,
) -> Import:
    imported = _uploading(session, import_id, user)
    if seq != imported.pieces_received + 1 or seq > imported.pieces:
        raise ImportRefused(ImportRefusal.OUT_OF_ORDER)
    if len(data) != _piece_size(imported, seq):
        raise ImportRefused(ImportRefusal.BAD_PIECE)
    run = own_run(session, imported)
    raw_store.write_bytes(imported.scan_id, run.id, f"{UPLOAD_PART}-{seq:05d}", data)
    imported.pieces_received = seq
    imported.updated_at = now
    session.flush()
    return imported


def finish_upload(session: Session, import_id: int, *, user: User | None, now: datetime) -> Import:
    imported = _uploading(session, import_id, user)
    if imported.pieces_received < imported.pieces:
        raise ImportRefused(ImportRefusal.INCOMPLETE)
    imported.state = ImportState.CHECKING
    imported.updated_at = now
    session.flush()
    return imported


@dataclass(frozen=True)
class ServerFile:
    path: Path
    size_bytes: int


class _Changed(Exception):
    pass


def _identity(path: Path) -> Identity | None:
    return folder_identity(os.fsencode(path))


def _opened(name: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except OSError as error:
        if error.errno in _MOVED:
            raise _Changed from None
        raise


class _NotAFile(Exception):
    pass


def _own_files(settings: Settings) -> set[Identity]:
    own: set[Identity] = set()
    places = [settings.data_dir / name for name in _listed(settings.data_dir)]
    key = guarded_key_file(settings)
    if key is not None:
        places.append(key)
    for place in places:
        try:
            held = os.stat(place, follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(held.st_mode) and held.st_ino:
            own.add((held.st_dev, held.st_ino))
    return own


def _listed(folder: Path) -> list[str]:
    try:
        return os.listdir(folder)
    except OSError:
        return []


def final_path(descriptor: int) -> str | None:
    if sys.platform != "win32":
        return None
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetFinalPathNameByHandleW(
        msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0
    )
    if length == 0 or length >= len(buffer):
        raise _Changed
    shown = buffer.value
    if shown.startswith("\\\\?\\UNC\\"):
        return "\\\\" + shown[len("\\\\?\\UNC\\") :]
    return shown.removeprefix("\\\\?\\")


def _open_by_folders(path: Path, base: Path) -> int:
    names = path.relative_to(base).parts
    folder = _opened(base, _FOLDER)
    try:
        for name in names[:-1]:
            inner = _opened(name, _FOLDER, dir_fd=folder)
            os.close(folder)
            folder = inner
        if not names:
            return os.dup(folder)
        mode = os.stat(names[-1], dir_fd=folder, follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            raise _Changed
        if not stat.S_ISREG(mode):
            raise _NotAFile
        return _opened(names[-1], _OPEN_FILE, dir_fd=folder)
    finally:
        os.close(folder)


def _open_by_identity(path: Path, seen: Identity | None) -> int:
    descriptor = _opened(path, _OPEN_FILE)
    try:
        held = os.fstat(descriptor)
        now = None if held.st_ino == 0 else (held.st_dev, held.st_ino)
        if seen is not None and now is not None and now != seen:
            raise _Changed
        try:
            again = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise _Changed from None
        if again != path:
            raise _Changed
        opened = final_path(descriptor)
        if opened is not None and os.path.normcase(opened) != os.path.normcase(str(path)):
            raise _Changed
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def open_server_file(text: str, settings: Settings) -> tuple[ServerFile, int]:
    if len(text) > SERVER_PATH_CHARS:
        raise ImportRefused(ImportRefusal.PATH_TOO_LONG)
    found = contained_file(
        text,
        bases=settings.scan_root_bases,
        data_dir=settings.data_dir,
        key_file=guarded_key_file(settings),
    )
    if isinstance(found, RootRefusal):
        raise ImportRefused(_FROM_ROOT.get(found, ImportRefusal.OUTSIDE_BASES))
    if len(str(found)) > SERVER_PATH_CHARS:
        raise ImportRefused(ImportRefusal.PATH_TOO_LONG)
    base = containing_base(found, settings.scan_root_bases)
    if base is None:
        raise ImportRefused(ImportRefusal.OUTSIDE_BASES)
    try:
        if _BY_FOLDERS:
            descriptor = _open_by_folders(found, base)
        else:
            descriptor = _open_by_identity(found, _identity(found))
    except _Changed:
        raise ImportRefused(ImportRefusal.CHANGED) from None
    except _NotAFile:
        raise ImportRefused(ImportRefusal.NOT_A_FILE) from None
    except OSError:
        raise ImportRefused(ImportRefusal.UNREADABLE_FILE) from None
    try:
        held = os.fstat(descriptor)
        if not stat.S_ISREG(held.st_mode):
            raise ImportRefused(ImportRefusal.NOT_A_FILE)
        if held.st_ino and (held.st_dev, held.st_ino) in _own_files(settings):
            raise ImportRefused(ImportRefusal.OWN_FILE)
        _bounded_size(held.st_size)
    except BaseException:
        os.close(descriptor)
        raise
    return ServerFile(found, held.st_size), descriptor


def check_server_file(text: str, settings: Settings) -> ServerFile:
    found, descriptor = open_server_file(text, settings)
    os.close(descriptor)
    return found


def from_server_file(
    session: Session,
    admin: User,
    *,
    tool: ToolName,
    target: ImportTarget,
    path: str,
    settings: Settings,
    now: datetime,
) -> Import:
    found = check_server_file(path, settings)
    return _made(
        session,
        admin,
        tool=tool,
        target=target,
        source=ImportSource.SERVER_FILE,
        state=ImportState.CHECKING,
        size_bytes=found.size_bytes,
        client_name=None,
        server_path=str(found.path),
        now=now,
    )


def confirm(session: Session, import_id: int, *, user: User | None) -> Import:
    imported = _import(session, import_id)
    _owned(imported, user, admin_too=True)
    _refuse_ended(imported)
    if imported.state in (ImportState.RECORDING, ImportState.RECORDED):
        raise ImportRefused(ImportRefusal.CONFIRMED)
    if imported.state is not ImportState.CHECKED:
        raise ImportRefused(ImportRefusal.NOT_CHECKED)
    imported.state = ImportState.RECORDING
    session.flush()
    return imported


def _discarded(session: Session, imported: Import, raw_store: RawStore, now: datetime) -> None:
    run = own_run(session, imported)
    run.state = ToolRunState.CANCELLED
    run.raw_parts = []
    run.finished_at = now
    scan = own_scan(session, imported)
    scan.state = ScanState.CANCELLED
    scan.finished_at = now
    imported.state = ImportState.DISCARDED
    imported.updated_at = now
    session.flush()
    raw_store.remove_parts(imported.scan_id, run.id)


def discard(
    session: Session, import_id: int, *, user: User | None, raw_store: RawStore, now: datetime
) -> Import:
    imported = _import(session, import_id)
    _owned(imported, user, admin_too=True)
    _refuse_ended(imported)
    if imported.state in JOB_STATES:
        raise ImportRefused(ImportRefusal.BUSY)
    if imported.state is ImportState.RECORDED:
        raise ImportRefused(ImportRefusal.RECORDED)
    _discarded(session, imported, raw_store, now)
    return imported


def expires_at(imported: Import) -> datetime | None:
    if imported.state is ImportState.UPLOADING:
        return imported.updated_at + UPLOAD_EXPIRES
    if imported.state is ImportState.CHECKED and imported.checked_at is not None:
        return imported.checked_at + CHECKED_EXPIRES
    return None


def expire_imports(session: Session, raw_store: RawStore, now: datetime) -> list[int]:
    stale = list(
        session.scalars(
            select(Import)
            .where(
                or_(
                    and_(
                        Import.state == ImportState.UPLOADING,
                        Import.updated_at < now - UPLOAD_EXPIRES,
                    ),
                    and_(
                        Import.state == ImportState.CHECKED,
                        Import.checked_at < now - CHECKED_EXPIRES,
                    ),
                )
            )
            .order_by(Import.id)
        )
    )
    for imported in stale:
        _discarded(session, imported, raw_store, now)
        audit.record(
            session,
            AuditAction.IMPORT_DISCARDED,
            actor=None,
            detail={"import_id": imported.id, "expired": True},
            at=now,
        )
    return [imported.id for imported in stale]


def _ids(name: str, ids: Collection[int]) -> BindParameter[int]:
    return bindparam(name, sorted(ids), expanding=True, literal_execute=True)


def _chunks(ids: Sequence[int]) -> list[Sequence[int]]:
    return [ids[at : at + _CHUNK] for at in range(0, len(ids), _CHUNK)]


@dataclass(frozen=True)
class _Doomed:
    runs: tuple[int, ...]
    findings: tuple[int, ...] = field(repr=False)
    secrets: tuple[int, ...] = field(repr=False)


def _doomed(session: Session, imported: Import) -> _Doomed:
    own = own_run(session, imported)
    runs = tuple(
        session.scalars(
            select(ToolRun.id).where(or_(ToolRun.id == own.id, ToolRun.parts_run_id == own.id))
        )
    )
    theirs = select(Sighting.finding_id).where(Sighting.tool_run_id.in_(_ids("runs", runs)))
    others = select(Sighting.finding_id).where(Sighting.tool_run_id.not_in(_ids("others", runs)))
    findings = tuple(
        session.scalars(
            select(Finding.id)
            .where(Finding.id.in_(theirs), Finding.id.not_in(others))
            .order_by(Finding.id)
        )
    )
    going = set(findings)
    held: set[int] = set()
    for chunk in _chunks(findings):
        held |= {
            secret_id
            for secret_id in session.scalars(
                select(Finding.secret_id).where(Finding.id.in_(_ids("f", chunk)))
            )
            if secret_id is not None
        }
    kept: set[int] = set()
    for chunk in _chunks(sorted(held)):
        for secret_id, finding_id in session.execute(
            select(Finding.secret_id, Finding.id).where(Finding.secret_id.in_(_ids("s", chunk)))
        ):
            if finding_id not in going and secret_id is not None:
                kept.add(secret_id)
    return _Doomed(runs, findings, tuple(sorted(held - kept)))


def _triaged(session: Session, doomed: _Doomed) -> int:
    secrets: set[int | None] = set()
    findings: set[int | None] = set()
    for chunk in _chunks(doomed.secrets):
        for model in (StatusChange, Note):
            secrets |= set(
                session.scalars(
                    select(model.secret_id).where(model.secret_id.in_(_ids("s", chunk)))
                )
            )
    for chunk in _chunks(doomed.findings):
        for model in (StatusChange, Note):
            findings |= set(
                session.scalars(
                    select(model.finding_id).where(model.finding_id.in_(_ids("f", chunk)))
                )
            )
    return len(secrets - {None}) + len(findings - {None})


def _recorded_anything(session: Session, own: ToolRun) -> bool:
    if own.raw_parts:
        return True
    sighted = session.scalar(
        select(Sighting.finding_id).where(Sighting.tool_run_id == own.id).limit(1)
    )
    return sighted is not None


def removable(session: Session, imported: Import) -> bool:
    if imported.state not in (ImportState.RECORDED, ImportState.FAILED):
        return False
    return _recorded_anything(session, own_run(session, imported))


def _removable(session: Session, imported: Import) -> None:
    if imported.state in (ImportState.UPLOADING, ImportState.CHECKED):
        raise ImportRefused(ImportRefusal.NOT_RECORDED)
    if imported.state in JOB_STATES:
        raise ImportRefused(ImportRefusal.BUSY)
    if imported.state in _ENDED:
        raise ImportRefused(ImportRefusal.ENDED)
    own = own_run(session, imported)
    if not _recorded_anything(session, own):
        raise ImportRefused(ImportRefusal.NOT_RECORDED)
    busy = session.scalar(
        select(ToolRun.id)
        .where(ToolRun.parts_run_id == own.id, ToolRun.state.in_(UNFINISHED_RUN))
        .limit(1)
    )
    if busy is not None:
        raise ImportRefused(ImportRefusal.BUSY)


def _forget_its_reports(session: Session, doomed: _Doomed) -> set[int]:
    sighted = select(Sighting.finding_id).where(Sighting.tool_run_id.in_(_ids("runs", doomed.runs)))
    first = (
        select(Sighting.finding_id, func.min(Sighting.tool_run_id).label("first"))
        .where(Sighting.finding_id.in_(sighted))
        .group_by(Sighting.finding_id)
        .subquery()
    )
    written = select(first.c.finding_id).where(first.c.first.in_(_ids("written_by", doomed.runs)))
    session.execute(
        update(Finding)
        .where(Finding.id.in_(written), Finding.meta_from == MetaFrom.REPORT)
        .values(
            author_name="",
            author_email="",
            authored_at=None,
            message_sealed=None,
            message_cut=False,
            meta_from=MetaFrom.NONE,
        )
        .execution_options(synchronize_session=False)
    )
    return {
        secret_id
        for secret_id in session.scalars(
            select(Finding.secret_id).distinct().where(Finding.id.in_(sighted))
        )
        if secret_id is not None
    }


def _newest(session: Session, model: type[StatusChange] | type[Note], doomed: _Doomed) -> int:
    newest = 0
    for column, ids in ((model.finding_id, doomed.findings), (model.secret_id, doomed.secrets)):
        for chunk in _chunks(ids):
            found = session.scalar(select(func.max(model.id)).where(column.in_(_ids("i", chunk))))
            newest = max(newest, found or 0)
    return newest


def _note_versions(session: Session, doomed: _Doomed) -> list[int]:
    count = versions = 0
    for column, ids in ((Note.finding_id, doomed.findings), (Note.secret_id, doomed.secrets)):
        for chunk in _chunks(ids):
            many, summed = session.execute(
                select(func.count(), func.coalesce(func.sum(Note.version), 0)).where(
                    column.in_(_ids("i", chunk))
                )
            ).one()
            count, versions = count + int(many), versions + int(summed)
    return [count, versions]


def _counted(session: Session, doomed: _Doomed) -> RemovalCounts:
    plan = {
        "findings": list(doomed.findings),
        "secrets": list(doomed.secrets),
        "status_change": _newest(session, StatusChange, doomed),
        "note": _newest(session, Note, doomed),
        "note_versions": _note_versions(session, doomed),
    }
    digest = hashlib.sha256(json.dumps(plan, separators=(",", ":")).encode()).hexdigest()
    return RemovalCounts(
        len(doomed.findings), len(doomed.secrets), _triaged(session, doomed), digest
    )


def removal_counts(session: Session, import_id: int) -> RemovalCounts:
    imported = _import(session, import_id)
    _removable(session, imported)
    return _counted(session, _doomed(session, imported))


def removed_subjects(session: Session, import_id: int) -> list[Subject]:
    imported = _import(session, import_id)
    doomed = _doomed(session, imported)
    named = [Subject(SubjectKind.SECRET, secret_id) for secret_id in doomed.secrets]
    for chunk in _chunks(doomed.findings):
        named += [
            Subject(SubjectKind.FINDING, finding_id)
            for finding_id in session.scalars(
                select(Finding.id).where(
                    Finding.id.in_(_ids("f", chunk)), Finding.secret_id.is_(None)
                )
            )
        ]
    return named


def remove(
    session: Session,
    import_id: int,
    *,
    digest: str,
    raw_store: RawStore,
    user: User | None,
    now: datetime,
) -> RemovalCounts:
    imported = _import(session, import_id)
    _removable(session, imported)
    doomed = _doomed(session, imported)
    counts = _counted(session, doomed)
    if not hmac.compare_digest(counts.digest, digest):
        raise ImportRefused(ImportRefusal.REMOVAL_CHANGED)
    touched = _forget_its_reports(session, doomed)
    for chunk in _chunks(doomed.findings):
        for model in (StatusChange, Note):
            session.execute(delete(model).where(model.finding_id.in_(_ids("f", chunk))))
    for chunk in _chunks(doomed.secrets):
        for model in (StatusChange, Note):
            session.execute(delete(model).where(model.secret_id.in_(_ids("s", chunk))))
    session.execute(delete(Sighting).where(Sighting.tool_run_id.in_(_ids("runs", doomed.runs))))
    for chunk in _chunks(doomed.findings):
        session.execute(delete(Finding).where(Finding.id.in_(_ids("f", chunk))))
    for chunk in _chunks(doomed.secrets):
        session.execute(delete(Secret).where(Secret.id.in_(_ids("s", chunk))))
    recompute_imported_kinds(session, touched - set(doomed.secrets))
    own = own_run(session, imported)
    session.execute(
        update(ToolRun)
        .where(ToolRun.id.in_(_ids("runs", doomed.runs)))
        .values(findings_count=0)
        .execution_options(synchronize_session=False)
    )
    own.raw_parts = []
    imported.state = ImportState.REMOVED
    imported.removed_at = now
    imported.removed_by_user_id = None if user is None else user.id
    session.flush()
    raw_store.remove_parts(imported.scan_id, own.id)
    return counts
