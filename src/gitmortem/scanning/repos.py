import os
import threading
import time
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from gitmortem.db import like
from gitmortem.db.models import (
    DeletionState,
    Repository,
    RepositoryKind,
    RepositoryRefusal,
    RepositoryState,
    Scan,
    ScanKind,
    ToolRun,
    ToolRunState,
)
from gitmortem.gitrun import (
    GitCancelled,
    GitError,
    GitRunner,
    GitTimeout,
    ShadowProblem,
    ShadowRefused,
    WorktreesUnreadable,
    repo_tips,
    shadow_problem,
)
from gitmortem.scanning import roots
from gitmortem.scanning.roots import SkippedFolders

MAX_PER_PAGE = 200
MAX_SEARCH_CHARS = 256
MAX_PAGE = 1_000_000_000
WALK_SECONDS = 120

REFUSAL_OF: Mapping[ShadowProblem, RepositoryRefusal] = {
    ShadowProblem.LINKED_WORKTREE: RepositoryRefusal.UNREADABLE,
    ShadowProblem.OWN_ALTERNATES: RepositoryRefusal.OWN_ALTERNATES,
    ShadowProblem.OWN_HTTP_ALTERNATES: RepositoryRefusal.OWN_ALTERNATES,
    ShadowProblem.SHALLOW: RepositoryRefusal.SHALLOW,
    ShadowProblem.NOT_SHA1: RepositoryRefusal.SHA256,
    ShadowProblem.FOREIGN_COMMONDIR: RepositoryRefusal.UNREADABLE,
    ShadowProblem.FETCHES: RepositoryRefusal.CONFIG_FETCHES,
    ShadowProblem.REFS_OUTSIDE: RepositoryRefusal.OUTSIDE_ROOT,
    ShadowProblem.ODD_PATH: RepositoryRefusal.UNREADABLE,
    ShadowProblem.UNREADABLE: RepositoryRefusal.UNREADABLE,
}

_HISTORY_PATHS = (
    "config",
    "config.worktree",
    "info/attributes",
    "info/grafts",
    "objects",
    "objects/info/alternates",
    "refs",
    "reftable",
    "packed-refs",
    "HEAD",
    "shallow",
    "commondir",
    "worktrees",
    "logs",
    "modules",
)


@dataclass(frozen=True)
class RepoFacts:
    refusal: RepositoryRefusal | None
    commit_count: int | None
    size_bytes: int
    head: str | None

    @classmethod
    def refused(cls, refusal: RepositoryRefusal, size_bytes: int = 0) -> "RepoFacts":
        return cls(refusal=refusal, commit_count=None, size_bytes=size_bytes, head=None)


class InspectionCancelled(GitCancelled):
    def __init__(self) -> None:
        GitError.__init__(self, "inspect", -1, "the inspection was cancelled")


class WalkTimedOut(OSError):
    pass


def _past(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _history_leads_out(
    git_dir: Path,
    root: Path,
    skip: SkippedFolders,
    cancel: threading.Event | None,
    deadline: float | None,
) -> bool:

    pending: list[Path] = []
    for inner in _HISTORY_PATHS:
        path = git_dir / inner
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        real = roots.real_inside(path, root)
        if real is None or skip.covers(real):
            return True
        if real.is_dir():
            pending.append(real)
    walked: set[roots.Identity | Path] = set()
    while pending:
        if cancel is not None and cancel.is_set():
            raise InspectionCancelled
        if _past(deadline):
            raise WalkTimedOut("the history walk ran out of time")
        folder = pending.pop()
        ident = roots.folder_identity(os.fsencode(folder))
        if folder in walked or ident in walked:
            continue
        if skip.is_skipped(folder, ident):
            return True
        walked |= {folder} if ident is None else {folder, ident}
        with os.scandir(folder) as listing:
            for entry in listing:
                if roots.is_link(entry):
                    real = roots.real_inside(Path(os.fsdecode(entry.path)), root)
                    if real is None or skip.covers(real):
                        return True
                    if real.is_dir():
                        pending.append(real)
                elif entry.is_dir(follow_symlinks=False):
                    pending.append(Path(os.fsdecode(entry.path)))
    return False


def _size(
    git_dir: Path,
    skip: SkippedFolders,
    cancel: threading.Event | None,
    deadline: float | None = None,
) -> int:
    total = 0
    pending = [os.fsencode(git_dir)]
    while pending:
        if cancel is not None and cancel.is_set():
            raise InspectionCancelled
        if _past(deadline):
            return total
        try:
            with os.scandir(pending.pop()) as listing:
                entries = list(listing)
        except OSError:
            continue
        for entry in entries:
            try:
                if roots.is_link(entry):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    ident = roots.folder_identity(entry.path)
                    if not skip.is_skipped(Path(os.fsdecode(entry.path)), ident):
                        pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def _fact(
    runner: GitRunner,
    args: Sequence[str],
    env: dict[str, str],
    cancel: threading.Event | None,
    ok_codes: Collection[int] = (0,),
    stdin: bytes | None = None,
) -> bytes | None:
    try:
        return runner.run(
            args,
            cwd=runner.private_dir,
            extra_env=env,
            ok_codes=ok_codes,
            cancel=cancel,
            stdin=stdin,
        )
    except GitTimeout:
        return None


def _commit_count(runner: GitRunner, git_dir: Path, cancel: threading.Event | None) -> int | None:
    try:
        tips = repo_tips(runner, git_dir, cancel=cancel)
    except GitTimeout:
        return None
    count = _fact(
        runner,
        ["rev-list", "--count", "--stdin"],
        {"GIT_DIR": str(git_dir)},
        cancel,
        stdin=b"".join(tip + b"\n" for tip in tips),
    )
    return None if count is None else int(count)


def contained_git_dir(
    git_dir: Path,
    root: Path,
    *,
    skip: Collection[Path] = (),
    cancel: threading.Event | None = None,
    deadline: float | None = None,
) -> Path | RepositoryRefusal:
    skipped = SkippedFolders(skip)
    try:
        root = root.resolve(strict=True)
        found = roots.real_inside(git_dir, root)
        if found is None or skipped.covers(found):
            return RepositoryRefusal.OUTSIDE_ROOT
        real = found
        is_dir = real.is_dir()
    except (OSError, RuntimeError, ValueError):
        return RepositoryRefusal.UNREADABLE
    if not is_dir:
        return RepositoryRefusal.UNREADABLE
    try:
        if _history_leads_out(real, root, skipped, cancel, deadline):
            return RepositoryRefusal.OUTSIDE_ROOT
    except OSError:
        return RepositoryRefusal.UNREADABLE
    return real


def inspect_repo(
    runner: GitRunner,
    git_dir: Path,
    root: Path,
    *,
    skip: Collection[Path] = (),
    cancel: threading.Event | None = None,
) -> RepoFacts:
    real = contained_git_dir(
        git_dir, root, skip=skip, cancel=cancel, deadline=time.monotonic() + WALK_SECONDS
    )
    if isinstance(real, RepositoryRefusal):
        return RepoFacts.refused(real)
    size = _size(real, SkippedFolders(skip), cancel, time.monotonic() + WALK_SECONDS)
    env = {"GIT_DIR": str(real)}
    try:
        problem = shadow_problem(runner, real, cancel=cancel)
        if problem is not None:
            return RepoFacts.refused(REFUSAL_OF[problem], size)
        count = _commit_count(runner, real, cancel)
        head = _fact(
            runner, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], env, cancel, (0, 1)
        )
    except GitCancelled:
        raise
    except (GitError, WorktreesUnreadable, ShadowRefused):
        return RepoFacts.refused(RepositoryRefusal.UNREADABLE, size)
    return RepoFacts(
        refusal=None,
        commit_count=count,
        size_bytes=size,
        head=None if head is None else head.strip().decode("ascii") or None,
    )


_C_ESCAPES = {
    0x07: "\\a",
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0B: "\\v",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _needs_quoting(byte: int) -> bool:
    return byte in _C_ESCAPES or byte < 0x20 or byte == 0x7F


def _c_quoted(raw: bytes, *, text: bool) -> str:
    out = ['"']
    for byte in raw:
        if byte in _C_ESCAPES:
            out.append(_C_ESCAPES[byte])
        elif byte < 0x20 or byte == 0x7F or (byte >= 0x80 and not text):
            out.append(f"\\{byte:03o}")
        else:
            out.append(chr(byte))
    out.append('"')
    quoted = "".join(out)
    return quoted.encode("latin-1").decode("utf-8") if text else quoted


def display_path(raw: bytes) -> str:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return _c_quoted(raw, text=False)
    if any(_needs_quoting(byte) for byte in raw):
        return _c_quoted(raw, text=True)
    return raw.decode("utf-8")


class RepositorySort(StrEnum):
    PATH = "path"
    NAME = "name"
    ORG = "org"
    KIND = "kind"
    STATE = "state"
    COMMIT_COUNT = "commit_count"
    SIZE_BYTES = "size_bytes"
    LAST_SEEN_AT = "last_seen_at"


_SORT_COLUMNS: Mapping[RepositorySort, tuple[InstrumentedAttribute[Any], ...]] = {
    RepositorySort.PATH: (Repository.scan_root_id, Repository.rel_path),
    RepositorySort.NAME: (Repository.name,),
    RepositorySort.ORG: (Repository.org,),
    RepositorySort.KIND: (Repository.kind,),
    RepositorySort.STATE: (Repository.state,),
    RepositorySort.COMMIT_COUNT: (Repository.commit_count,),
    RepositorySort.SIZE_BYTES: (Repository.size_bytes,),
    RepositorySort.LAST_SEEN_AT: (Repository.last_seen_at,),
}


def list_repositories(
    session: Session,
    *,
    root_id: int | None = None,
    state: RepositoryState | None = None,
    kind: RepositoryKind | None = None,
    text: str | None = None,
    sort: RepositorySort = RepositorySort.PATH,
    descending: bool = False,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[Repository], int]:
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    query = select(Repository).where(
        or_(Repository.deletion_state.is_(None), Repository.deletion_state != DeletionState.DELETED)
    )
    if root_id is not None:
        query = query.where(Repository.scan_root_id == root_id)
    if state is not None:
        query = query.where(Repository.state == state)
    if kind is not None:
        query = query.where(Repository.kind == kind)
    if text:
        query = query.where(Repository.display_path.ilike(like.anywhere(text), escape=like.ESCAPE))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    columns = (*_SORT_COLUMNS[sort], Repository.id)
    order = [column.desc() if descending else column.asc() for column in columns]
    rows = session.scalars(query.order_by(*order).limit(per_page).offset((page - 1) * per_page))
    return list(rows), total


@dataclass(frozen=True)
class ScanMark:
    last_scanned_at: datetime | None = None
    scanning: bool = False


UNSCANNED = ScanMark()


def scan_marks(session: Session, repository_ids: Collection[int]) -> dict[int, ScanMark]:
    ids = list(repository_ids)
    if not ids:
        return {}
    finished: dict[int, datetime | None] = {
        repository_id: at
        for repository_id, at in session.execute(
            select(ToolRun.repository_id, func.max(ToolRun.finished_at))
            .join(Scan, Scan.id == ToolRun.scan_id)
            .join(Repository, Repository.id == ToolRun.repository_id)
            .where(
                ToolRun.repository_id.in_(ids),
                Scan.kind == ScanKind.SCAN,
                ToolRun.state == ToolRunState.DONE,
                ToolRun.started_at >= Repository.first_seen_at,
            )
            .group_by(ToolRun.repository_id)
        )
    }
    scanning = set(
        session.scalars(
            select(ToolRun.repository_id)
            .join(Scan, Scan.id == ToolRun.scan_id)
            .where(
                ToolRun.repository_id.in_(ids),
                Scan.kind == ScanKind.SCAN,
                ToolRun.state.in_((ToolRunState.QUEUED, ToolRunState.RUNNING)),
            )
            .distinct()
        )
    )
    return {
        repository_id: ScanMark(finished.get(repository_id), repository_id in scanning)
        for repository_id in ids
        if repository_id in finished or repository_id in scanning
    }


class Scanned(StrEnum):
    ANY = "any"
    NEVER = "never"
    SCANNED = "scanned"
    SCANNING = "scanning"


class RepositoryListSort(StrEnum):
    PATH = "path"
    ORG = "org"
    NAME = "name"
    KIND = "kind"
    COMMITS = "commits"
    SIZE = "size"
    STATE = "state"
    SCANNED = "scanned"


MAX_LIST_PER_PAGE = 500
MAX_ORG_CHOICES = 50


@dataclass(frozen=True)
class RepositoryFilters:
    text: str = ""
    orgs: tuple[str, ...] = ()
    no_org: bool = False
    kinds: tuple[RepositoryKind, ...] = ()
    states: tuple[RepositoryState, ...] = ()
    scanned: Scanned = Scanned.ANY


@dataclass(frozen=True)
class Matching:
    root_id: int
    filters: RepositoryFilters
    excluded: tuple[int, ...] = ()
    included: tuple[int, ...] = ()


NO_ORG_LABEL = "No org"


@dataclass(frozen=True)
class RepositoryCounts:
    matching_scannable: int
    root_scannable: int
    root_unscanned: int


def _last_scanned() -> Any:
    return (
        select(func.max(ToolRun.finished_at))
        .join(Scan, Scan.id == ToolRun.scan_id)
        .where(
            ToolRun.repository_id == Repository.id,
            Scan.kind == ScanKind.SCAN,
            ToolRun.state == ToolRunState.DONE,
            ToolRun.started_at >= Repository.first_seen_at,
        )
        .correlate(Repository)
        .scalar_subquery()
    )


def _scanning() -> Any:
    return (
        select(ToolRun.id)
        .join(Scan, Scan.id == ToolRun.scan_id)
        .where(
            ToolRun.repository_id == Repository.id,
            Scan.kind == ScanKind.SCAN,
            ToolRun.state.in_((ToolRunState.QUEUED, ToolRunState.RUNNING)),
        )
        .correlate(Repository)
        .exists()
    )


def _never_scanned() -> Any:
    return _last_scanned().is_(None) & ~_scanning()


def _in_root(root_id: int) -> list[Any]:
    return [
        Repository.scan_root_id == root_id,
        or_(
            Repository.deletion_state.is_(None), Repository.deletion_state != DeletionState.DELETED
        ),
    ]


def _filtered(filters: RepositoryFilters) -> list[Any]:
    where: list[Any] = []
    if filters.text:
        pattern = like.anywhere(filters.text)
        where.append(
            or_(
                *(
                    column.ilike(pattern, escape=like.ESCAPE)
                    for column in (Repository.org, Repository.name, Repository.display_path)
                )
            )
        )
    if filters.orgs and filters.no_org:
        where.append(or_(Repository.org.in_(filters.orgs), Repository.org.is_(None)))
    elif filters.orgs:
        where.append(Repository.org.in_(filters.orgs))
    elif filters.no_org:
        where.append(Repository.org.is_(None))
    if filters.kinds:
        where.append(Repository.kind.in_(filters.kinds))
    if filters.states:
        where.append(Repository.state.in_(filters.states))
    if filters.scanned is Scanned.NEVER:
        where.append(_never_scanned())
    elif filters.scanned is Scanned.SCANNED:
        where.append(_last_scanned().is_not(None))
    elif filters.scanned is Scanned.SCANNING:
        where.append(_scanning())
    return where


def _list_order(sort: RepositoryListSort, descending: bool) -> list[Any]:
    keys: dict[RepositoryListSort, tuple[Any, ...]] = {
        RepositoryListSort.PATH: (Repository.display_path,),
        RepositoryListSort.ORG: (Repository.org,),
        RepositoryListSort.NAME: (Repository.name,),
        RepositoryListSort.KIND: (Repository.kind,),
        RepositoryListSort.COMMITS: (Repository.commit_count,),
        RepositoryListSort.SIZE: (Repository.size_bytes,),
        RepositoryListSort.STATE: (Repository.state,),
        RepositoryListSort.SCANNED: (_last_scanned(),),
    }
    chosen = [key.desc() if descending else key.asc() for key in keys[sort]]
    return [*chosen, Repository.display_path.asc(), Repository.id.asc()]


def _count(session: Session, *where: Any) -> int:
    return session.scalar(select(func.count()).select_from(Repository).where(*where)) or 0


def repository_page(
    session: Session,
    root_id: int,
    filters: RepositoryFilters,
    *,
    sort: RepositoryListSort,
    descending: bool,
    page: int,
    per_page: int,
) -> tuple[list[Repository], int, RepositoryCounts]:
    per_page = max(1, min(per_page, MAX_LIST_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    root = _in_root(root_id)
    where = [*root, *_filtered(filters)]
    total = _count(session, *where)
    rows = session.scalars(
        select(Repository)
        .where(*where)
        .order_by(*_list_order(sort, descending))
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    scannable = and_(
        Repository.state == RepositoryState.SCANNABLE, Repository.deletion_state.is_(None)
    )
    counts = RepositoryCounts(
        matching_scannable=_count(session, *where, scannable),
        root_scannable=_count(session, *root, scannable),
        root_unscanned=_count(session, *root, scannable, _never_scanned()),
    )
    return list(rows), total, counts


def matching_scannable_ids(session: Session, root_id: int, filters: RepositoryFilters) -> list[int]:
    where = [
        *_in_root(root_id),
        *_filtered(filters),
        Repository.state == RepositoryState.SCANNABLE,
        Repository.deletion_state.is_(None),
    ]
    return list(session.scalars(select(Repository.id).where(*where).order_by(Repository.id)))


def org_choices(session: Session, root_id: int, text: str) -> list[tuple[str, int]]:
    query = (
        select(func.coalesce(Repository.org, ""), func.count())
        .where(*_in_root(root_id))
        .group_by(Repository.org)
    )
    if text:
        named: ColumnElement[bool] = Repository.org.ilike(like.anywhere(text), escape=like.ESCAPE)
        if text.casefold() in NO_ORG_LABEL.casefold():
            named = or_(named, Repository.org.is_(None))
        query = query.where(named)
    query = query.order_by(func.count().desc(), Repository.org).limit(MAX_ORG_CHOICES)
    return [(org, count) for org, count in session.execute(query)]
