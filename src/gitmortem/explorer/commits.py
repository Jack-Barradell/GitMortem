import hashlib
import re
import threading
import time
from array import array
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import accumulate
from pathlib import Path
from typing import Literal

from gitmortem.explorer.access import Unavailable, git_read, is_commit, unavailable_for
from gitmortem.gitread import OBJECT_ID
from gitmortem.gitrun import (
    GitError,
    GitOutputTooLarge,
    GitRunner,
    GitTimeout,
    ShadowRefused,
    WorktreesUnreadable,
    repo_tips,
)

__all__ = [
    "HISTORY_MARGIN_SECONDS",
    "HISTORY_PAGE",
    "HISTORY_SECONDS",
    "MAX_COMMIT_BYTES",
    "MAX_HISTORY_SCAN",
    "MAX_HISTORY_SKIP",
    "MAX_MAPS",
    "MAX_MAP_COMMITS",
    "MAX_REFS",
    "MAX_REF_LISTING",
    "MAX_REV_LIST",
    "MAX_SUBJECT_CHARS",
    "BadSkip",
    "ChildrenMap",
    "Commit",
    "HistoryPage",
    "HistoryRow",
    "Ident",
    "MalformedCommit",
    "Ref",
    "RefKind",
    "RefList",
    "children",
    "children_map",
    "forget_children_maps",
    "head",
    "history_page",
    "parse_commit",
    "read_commit",
    "refs",
]

HISTORY_PAGE = 50
MAX_HISTORY_SKIP = 100_000
MAX_HISTORY_SCAN = 50_000
HISTORY_SECONDS = 20
HISTORY_MARGIN_SECONDS = 2
MAX_SUBJECT_CHARS = 2000
MAX_COMMIT_BYTES = 1 << 20
MAX_MAP_COMMITS = 1_000_000
MAX_MAPS = 8
MAX_REFS = 10_000
MAX_REV_LIST = 128 << 20
MAX_REF_LISTING = 16 << 20

_FIRST_BATCH = 64
_MOST_BATCH = 4096
_BATCH_BYTES = 16 << 20
_HEX = re.compile(rb"[0-9a-fA-F]{40}")
_SHA1_ID = re.compile(rb"[0-9a-f]{40}")
_DATE = re.compile(rb"\s*(\d+)\s+([+-])(\d\d)(\d\d)\s*")
_ID_BYTES = 20
_HEAD_BYTES = 128

RefKind = Literal["branch", "tag", "remote", "other"]
_REF_KINDS: tuple[tuple[bytes, RefKind], ...] = (
    (b"refs/heads/", "branch"),
    (b"refs/tags/", "tag"),
    (b"refs/remotes/", "remote"),
)


class MalformedCommit(ValueError):
    pass


class BadSkip(ValueError):
    def __init__(self) -> None:
        super().__init__(f"a history page starts 0 to {MAX_HISTORY_SKIP} commits in")


@dataclass(frozen=True)
class Ident:
    name: str = field(repr=False)
    email: str = field(repr=False)
    at: datetime | None


@dataclass(frozen=True)
class Commit:
    id: str
    tree: str
    parents: tuple[str, ...]
    author: Ident
    committer: Ident
    message: str = field(repr=False)


@dataclass(frozen=True)
class HistoryRow:
    id: str
    parents: tuple[str, ...]
    author: Ident
    subject: str = field(repr=False)
    too_large: bool = False
    message: str = field(repr=False, default="")


@dataclass(frozen=True)
class HistoryPage:
    rows: tuple[HistoryRow, ...]
    next_skip: int | None
    scanned: int
    cut: bool
    unread: int


@dataclass(frozen=True)
class Ref:
    name: bytes = field(repr=False)
    kind: RefKind
    target: str | None


@dataclass(frozen=True)
class RefList:
    refs: tuple[Ref, ...]
    truncated: bool


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _when(rest: bytes) -> datetime | None:
    match = _DATE.fullmatch(rest)
    if match is None:
        return None
    seconds, sign, hours, minutes = match.groups()
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    try:
        zone = timezone(-offset if sign == b"-" else offset)
        return datetime.fromtimestamp(int(seconds), zone)
    except (ValueError, OverflowError, OSError):
        return None


def _ident(value: bytes | None) -> Ident:
    if value is None:
        return Ident("", "", None)
    opens = value.find(b"<")
    closes = value.find(b">", opens + 1) if opens != -1 else -1
    if closes == -1:
        return Ident(_text(value), "", None)
    when = _when(value[value.rfind(b">") + 1 :])
    return Ident(_text(value[:opens].rstrip()), _text(value[opens + 1 : closes]), when)


def _id_after(line: bytes, prefix: bytes) -> str | None:
    if not line.startswith(prefix) or _HEX.fullmatch(line[len(prefix) :]) is None:
        return None
    return line[len(prefix) :].decode("ascii").lower()


def parse_commit(raw: bytes) -> Commit:
    end = raw.find(b"\n\n")
    head, message = (raw.removesuffix(b"\n"), b"") if end == -1 else (raw[:end], raw[end + 2 :])
    lines = head.split(b"\n")
    tree = _id_after(lines[0], b"tree ")
    if tree is None:
        raise MalformedCommit("a commit's first header names its tree")
    parents = []
    at = 1
    while at < len(lines) and lines[at].startswith(b"parent "):
        parent = _id_after(lines[at], b"parent ")
        if parent is None:
            raise MalformedCommit("a commit's parent is an object id")
        parents.append(parent)
        at += 1
    headers: dict[bytes, bytes] = {}
    for line in lines[at:]:
        if not line.startswith(b" "):
            key, _, value = line.partition(b" ")
            headers[key] = value
    oid = hashlib.sha1(b"commit %d\0" % len(raw) + raw, usedforsecurity=False).hexdigest()
    return Commit(
        id=oid,
        tree=tree,
        parents=tuple(parents),
        author=_ident(headers.get(b"author")),
        committer=_ident(headers.get(b"committer")),
        message=_text(message),
    )


def _lines(ids: Sequence[bytes]) -> bytes:
    return b"".join(oid + b"\n" for oid in ids)


def _rev_list_rows(out: bytes) -> list[bytes]:
    if out and not out.endswith(b"\n"):
        raise GitError("rev-list", 0, "git rev-list printed what is no commit")
    rows = out.split(b"\n")[:-1]
    for row in rows:
        if not all(_SHA1_ID.fullmatch(oid) for oid in row.split(b" ")):
            raise GitError("rev-list", 0, "git rev-list printed what is no commit")
    return rows


def _records(out: bytes, subcommand: str) -> list[bytes]:
    if out and not out.endswith(b"\n"):
        raise GitError(subcommand, 0, f"git {subcommand} did not end its listing")
    return out.split(b"\n")[:-1]


def _tips(runner: GitRunner, git_dir: Path, deadline: float) -> list[bytes]:
    return repo_tips(runner, git_dir, deadline=deadline, max_stdout=MAX_REV_LIST)


def _sizes(runner: GitRunner, git_dir: Path, ids: Sequence[bytes], deadline: float) -> list[int]:
    out = git_read(
        runner,
        git_dir,
        ["cat-file", "--batch-check"],
        deadline,
        stdin=_lines(ids),
        max_stdout=len(ids) * 80,
    )
    lines = _records(out, "cat-file")
    if len(lines) != len(ids):
        raise GitError("cat-file", 0, "git cat-file did not size each commit")
    sizes = []
    for oid, line in zip(ids, lines, strict=True):
        parts = line.split(b" ")
        if len(parts) != 3 or parts[:2] != [oid, b"commit"] or not parts[2].isdigit():
            raise GitError("cat-file", 0, "git cat-file sized what is not the commit")
        sizes.append(int(parts[2]))
    return sizes


def _read_commits(
    runner: GitRunner, git_dir: Path, batch: Sequence[tuple[bytes, int]], deadline: float
) -> list[Commit]:
    if not batch:
        return []
    headers = [b"%s commit %d\n" % (oid, size) for oid, size in batch]
    out = git_read(
        runner,
        git_dir,
        ["cat-file", "--batch"],
        deadline,
        stdin=_lines([oid for oid, _ in batch]),
        max_stdout=sum(
            len(header) + size + 1 for header, (_, size) in zip(headers, batch, strict=True)
        ),
    )
    found = []
    at = 0
    for header, (oid, size) in zip(headers, batch, strict=True):
        start = at + len(header)
        if out[at:start] != header or out[start + size : start + size + 1] != b"\n":
            raise GitError("cat-file", 0, "git cat-file did not give the commits asked for")
        commit = parse_commit(out[start : start + size])
        if commit.id != oid.decode("ascii"):
            raise MalformedCommit("a commit's bytes are not the object its id names")
        found.append(commit)
        at = start + size + 1
    if at != len(out):
        raise GitError("cat-file", 0, "git cat-file gave more than the commits asked for")
    return found


def read_commit(
    runner: GitRunner, git_dir: Path, commit: str, *, deadline: float
) -> Commit | Unavailable:
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
        oid = commit.encode("ascii")
        (size,) = _sizes(runner, git_dir, [oid], deadline)
        if size > MAX_COMMIT_BYTES:
            return Unavailable.TOO_LARGE
        (found,) = _read_commits(runner, git_dir, [(oid, size)], deadline)
    except GitError as error:
        return unavailable_for(error)
    except MalformedCommit:
        return Unavailable.UNREADABLE
    return found


@dataclass(frozen=True, eq=False)
class ChildrenMap:
    ids: bytes = field(repr=False)
    starts: "array[int]" = field(repr=False)
    edges: "array[int]" = field(repr=False)

    @property
    def commits(self) -> int:
        return len(self.ids) // _ID_BYTES

    def _id(self, place: int) -> bytes:
        return self.ids[place * _ID_BYTES : (place + 1) * _ID_BYTES]

    def of(self, commit: str) -> tuple[str, ...]:
        key = bytes.fromhex(commit)
        low, high = 0, self.commits
        while low < high:
            middle = (low + high) // 2
            if self._id(middle) < key:
                low = middle + 1
            else:
                high = middle
        if self._id(low) != key:
            return ()
        places = self.edges[self.starts[low] : self.starts[low + 1]]
        return tuple(self._id(place).hex() for place in places)

    @classmethod
    def from_rev_list(cls, out: bytes) -> "ChildrenMap | None":
        rows = _rev_list_rows(out)
        if len(rows) > MAX_MAP_COMMITS:
            return None
        ordered = sorted({row[:40] for row in rows})
        place = {oid: n for n, oid in enumerate(ordered)}
        counts = [0] * (len(ordered) + 1)
        try:
            for row in rows:
                for parent in row[41:].split():
                    counts[place[parent] + 1] += 1
            starts = array("I", accumulate(counts))
            filled = array("I", starts)
            edges = array("I", bytes(4 * starts[-1]))
            for row in rows:
                child = place[row[:40]]
                for parent in row[41:].split():
                    at = place[parent]
                    edges[filled[at]] = child
                    filled[at] += 1
        except KeyError:
            raise GitError("rev-list", 0, "git rev-list named a parent it did not list") from None
        return cls(bytes.fromhex(b"".join(ordered).decode("ascii")), starts, edges)


_maps: OrderedDict[Path, tuple[str, ChildrenMap | None]] = OrderedDict()
_maps_lock = threading.Lock()


def forget_children_maps() -> None:
    with _maps_lock:
        _maps.clear()


def _held(git_dir: Path, fingerprint: str) -> tuple[bool, ChildrenMap | None]:
    with _maps_lock:
        held = _maps.get(git_dir)
        if held is None or held[0] != fingerprint:
            return False, None
        _maps.move_to_end(git_dir)
        return True, held[1]


def _hold(git_dir: Path, fingerprint: str, built: ChildrenMap | None) -> None:
    with _maps_lock:
        _maps[git_dir] = (fingerprint, built)
        _maps.move_to_end(git_dir)
        while len(_maps) > MAX_MAPS:
            _maps.popitem(last=False)


def children_map(runner: GitRunner, git_dir: Path, *, deadline: float) -> ChildrenMap | Unavailable:
    try:
        tips = _tips(runner, git_dir, deadline)
    except GitError as error:
        return unavailable_for(error)
    except WorktreesUnreadable:
        return Unavailable.UNREADABLE
    except ShadowRefused:
        return Unavailable.REFUSED
    fingerprint = hashlib.sha256(b"".join(sorted(tips))).hexdigest()
    known, built = _held(git_dir, fingerprint)
    if not known:
        try:
            listing = git_read(
                runner,
                git_dir,
                ["rev-list", "--parents", "--stdin"],
                deadline,
                stdin=_lines(tips),
                max_stdout=MAX_REV_LIST,
            )
            built = ChildrenMap.from_rev_list(listing)
        except GitOutputTooLarge:
            built = None
        except GitError as error:
            return unavailable_for(error)
        _hold(git_dir, fingerprint, built)
    return Unavailable.TOO_LARGE if built is None else built


def children(
    runner: GitRunner, git_dir: Path, commit: str, *, deadline: float
) -> tuple[str, ...] | Unavailable:
    try:
        if not is_commit(runner, git_dir, commit, deadline=deadline):
            return Unavailable.NOT_IN_HISTORY
    except GitError as error:
        return unavailable_for(error)
    found = children_map(runner, git_dir, deadline=deadline)
    return found if isinstance(found, Unavailable) else found.of(commit)


def head(runner: GitRunner, git_dir: Path, *, deadline: float) -> str | Unavailable:
    try:
        out = git_read(
            runner,
            git_dir,
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}"],
            deadline,
            ok_codes=(0, 1),
            max_stdout=_HEAD_BYTES,
        )
    except GitError as error:
        return unavailable_for(error)
    if not out:
        return Unavailable.NOT_IN_HISTORY
    if not out.endswith(b"\n") or OBJECT_ID.fullmatch(out[:-1]) is None:
        return Unavailable.UNREADABLE
    return out[:-1].decode("ascii")


_NO_IDENT = Ident("", "", None)


@dataclass(frozen=True)
class _Listed:
    oid: bytes
    parents: bytes
    size: int

    @property
    def readable(self) -> bool:
        return self.size <= MAX_COMMIT_BYTES


@dataclass(frozen=True)
class _Scanned:
    rows: list[HistoryRow]
    examined: int
    unread: int
    timed: bool


def _row(commit: Commit) -> HistoryRow:
    subject = commit.message.split("\n", 1)[0][:MAX_SUBJECT_CHARS]
    return HistoryRow(
        id=commit.id,
        parents=commit.parents,
        author=commit.author,
        subject=subject,
        message=commit.message,
    )


def _unread_row(item: _Listed) -> HistoryRow:
    parents = tuple(parent.decode("ascii") for parent in item.parents.split())
    return HistoryRow(item.oid.decode("ascii"), parents, _NO_IDENT, "", too_large=True)


def _matches(commit: Commit, query: str) -> bool:
    return query in commit.message or query in commit.author.name or query in commit.author.email


def _batches(listed: Sequence[_Listed]) -> list[list[_Listed]]:
    batches: list[list[_Listed]] = []
    most, at = _FIRST_BATCH, 0
    while at < len(listed):
        batch: list[_Listed] = []
        carried = 0
        while at < len(listed) and len(batch) < most:
            weight = listed[at].size if listed[at].readable else 0
            if batch and carried + weight > _BATCH_BYTES:
                break
            batch.append(listed[at])
            carried += weight
            at += 1
        batches.append(batch)
        most = min(most * 2, _MOST_BATCH)
    return batches


def _scan(
    runner: GitRunner,
    git_dir: Path,
    listed: Sequence[_Listed],
    query: str | None,
    *,
    until: float,
    deadline: float,
) -> _Scanned:
    rows: list[HistoryRow] = []
    examined = unread = 0
    for n, batch in enumerate(_batches(listed)):
        if n and time.monotonic() >= until:
            return _Scanned(rows, examined, unread, timed=True)
        wanted = [(item.oid, item.size) for item in batch if item.readable]
        try:
            read = iter(_read_commits(runner, git_dir, wanted, deadline))
        except GitTimeout:
            if not n:
                raise
            return _Scanned(rows, examined, unread, timed=True)
        for item in batch:
            examined += 1
            if not item.readable:
                if query is not None:
                    unread += 1
                    continue
                rows.append(_unread_row(item))
            else:
                commit = next(read)
                if query is not None and not _matches(commit, query):
                    continue
                rows.append(_row(commit))
            if len(rows) == HISTORY_PAGE:
                return _Scanned(rows, examined, unread, timed=False)
    return _Scanned(rows, examined, unread, timed=False)


def history_page(
    runner: GitRunner, git_dir: Path, *, skip: int, query: str | None, deadline: float
) -> HistoryPage | Unavailable:
    if not 0 <= skip <= MAX_HISTORY_SKIP:
        raise BadSkip
    until = min(time.monotonic() + HISTORY_SECONDS, deadline - HISTORY_MARGIN_SECONDS)
    window = HISTORY_PAGE if query is None else MAX_HISTORY_SCAN
    try:
        tips = _tips(runner, git_dir, deadline)
        rows = _rev_list_rows(
            git_read(
                runner,
                git_dir,
                ["rev-list", "--parents", f"--skip={skip}", f"--max-count={window + 1}", "--stdin"],
                deadline,
                stdin=_lines(tips),
                max_stdout=MAX_REV_LIST,
            )
        )
        more = len(rows) > window
        rows = rows[:window]
        sizes = _sizes(runner, git_dir, [row[:40] for row in rows], deadline)
        listed = [_Listed(row[:40], row[41:], size) for row, size in zip(rows, sizes, strict=True)]
        scanned = _scan(runner, git_dir, listed, query, until=until, deadline=deadline)
    except GitError as error:
        return unavailable_for(error)
    except (WorktreesUnreadable, MalformedCommit):
        return Unavailable.UNREADABLE
    except ShadowRefused:
        return Unavailable.REFUSED
    if len(scanned.rows) == HISTORY_PAGE:
        cut, goes_on = False, scanned.examined < len(listed) or more
    else:
        cut = goes_on = scanned.timed or more
    next_skip = skip + scanned.examined if goes_on else None
    if next_skip is not None and next_skip > MAX_HISTORY_SKIP:
        next_skip, cut = None, True
    return HistoryPage(
        rows=tuple(scanned.rows),
        next_skip=next_skip,
        scanned=scanned.examined,
        cut=cut,
        unread=scanned.unread,
    )


def _kind(name: bytes) -> RefKind:
    for prefix, kind in _REF_KINDS:
        if name.startswith(prefix):
            return kind
    return "other"


def _listed_refs(out: bytes) -> list[tuple[bytes, bytes]]:
    found = []
    for line in _records(out, "for-each-ref"):
        parts = line.split(b"\0")
        if len(parts) != 3 or not parts[1]:
            raise GitError("for-each-ref", 0, "git for-each-ref printed a ref it should not")
        oid, name, symref = parts
        if not oid and symref:
            continue
        if OBJECT_ID.fullmatch(oid) is None:
            raise GitError("for-each-ref", 0, "git for-each-ref printed a ref it should not")
        found.append((oid, name))
    return found


def _peeled(
    runner: GitRunner, git_dir: Path, ids: Sequence[bytes], deadline: float
) -> list[str | None]:
    asked = [oid + b"^{commit}" for oid in ids]
    out = git_read(
        runner,
        git_dir,
        ["cat-file", "--batch-check"],
        deadline,
        stdin=_lines(asked),
        max_stdout=len(ids) * 80,
    )
    lines = _records(out, "cat-file")
    if len(lines) != len(ids):
        raise GitError("cat-file", 0, "git cat-file did not peel each ref")
    targets: list[str | None] = []
    for name, line in zip(asked, lines, strict=True):
        parts = line.split(b" ")
        if line == name + b" missing":
            targets.append(None)
        elif len(parts) == 3 and parts[1] == b"commit" and OBJECT_ID.fullmatch(parts[0]):
            targets.append(parts[0].decode("ascii"))
        else:
            raise GitError("cat-file", 0, "git cat-file peeled a ref to what is no commit")
    return targets


def refs(runner: GitRunner, git_dir: Path, *, deadline: float) -> RefList | Unavailable:
    try:
        _tips(runner, git_dir, deadline)
        out = git_read(
            runner,
            git_dir,
            [
                "for-each-ref",
                f"--count={MAX_REFS + 1}",
                "--format=%(objectname)%00%(refname)%00%(symref)",
            ],
            deadline,
            max_stdout=MAX_REF_LISTING,
        )
        listed = _listed_refs(out)
        kept = listed[:MAX_REFS]
        targets = _peeled(runner, git_dir, [oid for oid, _ in kept], deadline)
    except GitError as error:
        return unavailable_for(error)
    except WorktreesUnreadable:
        return Unavailable.UNREADABLE
    except ShadowRefused:
        return Unavailable.REFUSED
    return RefList(
        refs=tuple(
            Ref(name=name, kind=_kind(name), target=target)
            for (_, name), target in zip(kept, targets, strict=True)
        ),
        truncated=len(listed) > MAX_REFS,
    )
