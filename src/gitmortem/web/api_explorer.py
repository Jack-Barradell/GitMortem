import time
from collections import ChainMap
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import batched
from pathlib import Path
from typing import Any

from apiflask import APIBlueprint, abort
from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.config import guarded_key_file
from gitmortem.crypto import Purpose
from gitmortem.db.models import Finding, FindingPlace, Role
from gitmortem.explorer import commits, known, search, trees
from gitmortem.explorer.access import (
    NoSuchRepository,
    Unavailable,
    checked_git_dir,
    holding_version,
    open_for_read,
)
from gitmortem.explorer.commits import BadSkip, Commit, HistoryPage, Ident, RefList
from gitmortem.explorer.known import KnownIndex, as_in_files
from gitmortem.explorer.search import BadQuery, NameHit, SearchResult
from gitmortem.explorer.trees import BadPath, FileContent, Folder
from gitmortem.gitread import FULL_HEX
from gitmortem.gitrun import GitRunner
from gitmortem.triage import classify, values
from gitmortem.triage.context import clean_file_text
from gitmortem.triage.query import latest_change_id
from gitmortem.triage.subjects import NoSuchSubject, Subject, SubjectKind, subject_key
from gitmortem.web.api_subjects import ID, message_line
from gitmortem.web.api_triage import VALUES_ROLE
from gitmortem.web.canary_check import possible_canaries
from gitmortem.web.dbsession import get_db, read_phase
from gitmortem.web.explorer_schemas import (
    CommitOut,
    CommitReadOut,
    EntryOut,
    ExplorerHistoryOut,
    FileIn,
    FileOut,
    FileShownOut,
    FirstFoundOut,
    FolderListOut,
    FolderOut,
    HeadCommitOut,
    HeadOut,
    HistoryIn,
    HistoryPageOut,
    HistoryRowOut,
    IdentOut,
    LineHitOut,
    MarkedSubjectOut,
    MarkOut,
    NameHitListOut,
    NameHitOut,
    NameHitsOut,
    NamesIn,
    PlaceOut,
    RefListOut,
    RefOut,
    RefsOut,
    SearchHitsOut,
    SearchIn,
    SearchOut,
    TreeQueryIn,
    UnavailableOut,
    VersionQueryIn,
    segment_out,
    shown,
    shown_name,
    spelled,
    utf16_offsets,
)
from gitmortem.web.scans import running_scans
from gitmortem.web.sealing import app_sealer
from gitmortem.web.security import require_role

bp = APIBlueprint("explorer", __name__, url_prefix="/api")
REPOSITORY = f"/repositories/{ID}"
READ_SECONDS = 30
SUBJECT_VALUE_SHOWN = 200
MAX_FILE_SUBJECTS = 10_000
MAX_PATH_FINDINGS = 100_000
LINES_A_QUERY = 500
VALUES_A_QUERY = 32
LINE_STRIP = " \t\r"
FILE_PLACES = (FindingPlace.LINE, FindingPlace.UNRESOLVED)
_NO_DATE = datetime.min.replace(tzinfo=UTC)
NO_SUCH_REPOSITORY = "No such repository."
NO_SUCH_FINDING = "No such finding."
NOT_A_COMMIT = "A commit is named by its 40 lowercase hexadecimal characters."
REPOSITORY_404 = "No such repository"
SCANNING_503 = "Scanning is not running"
VALUES_403 = "A user who may not see values; nothing was read"

Shown = Callable[[Mapping[Subject, str]], Mapping[Subject, str]]


def _as_stored(found: Mapping[Subject, str]) -> Mapping[Subject, str]:
    return found


@dataclass(frozen=True)
class _At:
    runner: GitRunner
    git_dir: Path
    deadline: float
    index: KnownIndex


@dataclass(frozen=True)
class _Read[T]:
    found: T | Unavailable
    index: KnownIndex = field(default_factory=lambda: KnownIndex({}))
    marks_dropped: bool = False
    integrity_failed: bool = False
    known: Mapping[Subject, str] = field(default_factory=dict, repr=False)


def _explore[T](
    repository_id: int,
    read: Callable[[_At], T | Unavailable],
    *,
    known_as: Shown | None = None,
    commit: str | None = None,
    version: int | None = None,
) -> _Read[T]:
    service = running_scans()
    dropped = False
    try:
        with read_phase() as db:
            repo = open_for_read(db, repository_id, version_id=version)
            if isinstance(repo, Unavailable):
                return _Read(repo)
            index = KnownIndex({})
            shown_known: Mapping[Subject, str] = {}
            if known_as is not None:
                try:
                    opened = values.Opened()
                    found = known.known_values(db, app_sealer(), repository_id, opened=opened)
                    shown_known = known_as(found)
                    index = KnownIndex(shown_known)
                except values.TooManyToDecrypt:
                    dropped = True
    except NoSuchRepository:
        abort(404, message=NO_SUCH_REPOSITORY)
    deadline = time.monotonic() + READ_SECONDS
    settings = service.settings
    bases, key_file = settings.scan_root_bases, guarded_key_file(settings)
    if commit is not None and version is None:
        git_dir = holding_version(
            service.runner,
            repo,
            commit,
            bases=bases,
            data_dir=settings.data_dir,
            key_file=key_file,
            deadline=deadline,
        )
    else:
        git_dir = checked_git_dir(
            service.runner,
            repo,
            bases=bases,
            data_dir=settings.data_dir,
            key_file=key_file,
            deadline=deadline,
        )
    if isinstance(git_dir, Unavailable):
        return _Read(git_dir)
    answer = read(_At(service.runner, git_dir, deadline, index))
    return _Read(answer, index, dropped, repo.integrity_failed, shown_known)


@bp.errorhandler(BadPath)
@bp.errorhandler(BadQuery)
@bp.errorhandler(BadSkip)
def _refused(error: ValueError) -> tuple[dict[str, Any], int]:
    return {"message": str(error), "detail": {}}, 422


def _ident_out(ident: Ident) -> IdentOut:
    return IdentOut(name=shown(ident.name), email=shown(ident.email), at=ident.at)


def _unavailable(reason: Unavailable) -> UnavailableOut:
    return UnavailableOut(unavailable=reason)


@bp.get(f"{REPOSITORY}/explore/tree", endpoint="tree")
@require_role(Role.ANALYST)
@bp.input(TreeQueryIn, location="query", arg_name="query")
@bp.output(FolderOut)
@bp.doc(responses={404: REPOSITORY_404, 503: SCANNING_503})
def explore_tree(id: int, query: TreeQueryIn) -> FolderOut:
    path = query.segments()
    done: _Read[Folder] = _explore(
        id,
        lambda at: trees.list_folder(
            at.runner, at.git_dir, query.commit, path, deadline=at.deadline
        ),
        commit=query.commit,
        version=query.version,
    )
    if isinstance(done.found, Unavailable):
        return FolderOut(_unavailable(done.found))
    return FolderOut(
        FolderListOut(
            entries=[
                EntryOut(
                    raw=spelled(entry.name),
                    name=shown_name(entry.name),
                    kind=entry.kind,
                    size=entry.size,
                    object_id=entry.object_id,
                )
                for entry in done.found.entries
            ],
            total=done.found.total,
            truncated=done.found.truncated,
        )
    )


@bp.get(f"{REPOSITORY}/commits/<commit>", endpoint="commit")
@require_role(VALUES_ROLE)
@bp.input(VersionQueryIn, location="query", arg_name="at")
@bp.output(CommitOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: REPOSITORY_404,
        422: "A commit that is not 40 lowercase hexadecimal characters",
        503: SCANNING_503,
    }
)
def explore_commit(id: int, commit: str, at: VersionQueryIn) -> CommitOut:
    if FULL_HEX.fullmatch(commit) is None:
        abort(422, message=NOT_A_COMMIT)

    def read(where: _At) -> tuple[Commit, tuple[str, ...] | Unavailable] | Unavailable:
        found = commits.read_commit(where.runner, where.git_dir, commit, deadline=where.deadline)
        if isinstance(found, Unavailable):
            return found
        return found, commits.children(where.runner, where.git_dir, commit, deadline=where.deadline)

    done = _explore(id, read, known_as=_as_stored, commit=commit, version=at.version)
    if isinstance(done.found, Unavailable):
        return CommitOut(_unavailable(done.found))
    read_commit, kids = done.found
    dropped = done.marks_dropped
    try:
        lines, cut = known.marked_message(done.index, read_commit.message)
    except values.TooManyToDecrypt:
        lines, cut = known.marked_message(KnownIndex({}), read_commit.message)
        dropped = True
    return CommitOut(
        CommitReadOut(
            id=read_commit.id,
            tree=read_commit.tree,
            parents=list(read_commit.parents),
            children=None if isinstance(kids, Unavailable) else list(kids),
            children_unavailable=kids if isinstance(kids, Unavailable) else None,
            author=_ident_out(read_commit.author),
            committer=_ident_out(read_commit.committer),
            message=[message_line(line) for line in lines],
            message_cut=cut,
            integrity_failed=done.integrity_failed,
            marks_dropped=dropped,
        )
    )


@bp.get(f"{REPOSITORY}/refs", endpoint="refs")
@require_role(Role.ANALYST)
@bp.input(VersionQueryIn, location="query", arg_name="at")
@bp.output(RefsOut)
@bp.doc(responses={404: REPOSITORY_404, 503: SCANNING_503})
def explore_refs(id: int, at: VersionQueryIn) -> RefsOut:
    done: _Read[RefList] = _explore(
        id,
        lambda where: commits.refs(where.runner, where.git_dir, deadline=where.deadline),
        version=at.version,
    )
    if isinstance(done.found, Unavailable):
        return RefsOut(_unavailable(done.found))
    return RefsOut(
        RefListOut(
            refs=[
                RefOut(name=shown_name(ref.name), kind=ref.kind, target=ref.target)
                for ref in done.found.refs
            ],
            truncated=done.found.truncated,
        )
    )


@bp.get(f"{REPOSITORY}/head", endpoint="head")
@require_role(Role.ANALYST)
@bp.input(VersionQueryIn, location="query", arg_name="at")
@bp.output(HeadOut)
@bp.doc(responses={404: REPOSITORY_404, 503: SCANNING_503})
def explore_head(id: int, at: VersionQueryIn) -> HeadOut:
    done: _Read[str] = _explore(
        id,
        lambda where: commits.head(where.runner, where.git_dir, deadline=where.deadline),
        version=at.version,
    )
    if isinstance(done.found, Unavailable):
        return HeadOut(_unavailable(done.found))
    return HeadOut(HeadCommitOut(commit=done.found))


@bp.post(f"{REPOSITORY}/explore/names", endpoint="names")
@require_role(Role.ANALYST)
@bp.input(NamesIn, arg_name="body")
@bp.output(NameHitsOut)
@bp.doc(
    responses={404: REPOSITORY_404, 422: "A commit or query out of its bounds", 503: SCANNING_503}
)
def explore_names(id: int, body: NamesIn) -> NameHitsOut:
    done: _Read[tuple[tuple[NameHit, ...], bool]] = _explore(
        id,
        lambda at: search.find_names(
            at.runner, at.git_dir, body.commit, body.query, deadline=at.deadline
        ),
        commit=body.commit,
        version=body.version,
    )
    if isinstance(done.found, Unavailable):
        return NameHitsOut(_unavailable(done.found))
    hits, cut = done.found
    return NameHitsOut(
        NameHitListOut(
            hits=[
                NameHitOut(path=[segment_out(part) for part in hit.path], kind=hit.kind)
                for hit in hits
            ],
            cut=cut,
        )
    )


NOT_IN_A_COMMIT = (
    "This finding is in a tag's message or in an object no commit holds, so there is no "
    "commit to open it at."
)


@bp.get(f"/findings/{ID}/place", endpoint="place")
@require_role(Role.ANALYST)
@bp.output(PlaceOut)
@bp.doc(responses={404: NO_SUCH_FINDING, 409: NOT_IN_A_COMMIT})
def finding_place(id: int) -> PlaceOut:
    found = (
        get_db()
        .execute(
            select(
                Finding.repository_id, Finding.commit, Finding.path, Finding.line, Finding.place
            ).where(Finding.id == id)
        )
        .first()
    )
    if found is None:
        abort(404, message=NO_SUCH_FINDING)
    repository_id, commit, path, line, place = found
    if place in (FindingPlace.TAG, FindingPlace.OBJECT):
        abort(409, message=NOT_IN_A_COMMIT)
    return PlaceOut(
        repository_id=repository_id,
        commit=commit,
        path=[segment_out(part) for part in path.split(b"/")],
        line=line,
    )


def _marks_out(text: str, marked: known.Marked, owners: Mapping[str, Subject]) -> list[MarkOut]:
    offsets = utf16_offsets(
        text, (at for m in marked.marks for at in (m.line_start, m.start, m.end))
    )
    return [
        MarkOut(
            line=m.line,
            start=offsets[m.start] - offsets[m.line_start],
            end=offsets[m.end] - offsets[m.line_start],
            subject=None if (owner := owners.get(m.value)) is None else subject_key(owner),
        )
        for m in marked.marks
    ]


def _owners(shown_known: Mapping[Subject, str]) -> dict[str, Subject]:
    owners: dict[str, Subject] = {}
    for subject in sorted(shown_known, key=lambda s: (s.kind is not SubjectKind.SECRET, s.id)):
        owners.setdefault(shown_known[subject], subject)
    return owners


@dataclass(frozen=True)
class _Recorded:
    finding_id: int
    subject: Subject
    commit: str
    line: int
    place: FindingPlace
    authored_at: datetime | None


@dataclass(frozen=True)
class _Lines:
    owners: dict[str, list[Subject]] = field(repr=False)
    unchecked: bool


def _recorded(
    db: Session, repository_id: int, commit: str, path: bytes
) -> tuple[list[_Recorded], bool]:
    rows = db.execute(
        select(
            Finding.id,
            Finding.secret_id,
            Finding.commit,
            Finding.line,
            Finding.place,
            Finding.authored_at,
        )
        .where(
            Finding.repository_id == repository_id,
            Finding.path == path,
            Finding.place.in_(FILE_PLACES),
        )
        .order_by(Finding.commit != commit, Finding.id)
        .limit(MAX_PATH_FINDINGS + 1)
    ).all()
    recorded = [
        _Recorded(
            finding_id=finding_id,
            subject=(
                Subject(SubjectKind.FINDING, finding_id)
                if secret_id is None
                else Subject(SubjectKind.SECRET, secret_id)
            ),
            commit=found_at,
            line=line,
            place=place,
            authored_at=authored_at,
        )
        for finding_id, secret_id, found_at, line, place, authored_at in rows
    ]
    return recorded[:MAX_PATH_FINDINGS], len(recorded) > MAX_PATH_FINDINGS


def _recorded_lines(
    db: Session, recorded: Sequence[_Recorded], wanted: Collection[Subject]
) -> _Lines:
    subjects = {each.finding_id: each.subject for each in recorded if each.subject in wanted}
    sealer = app_sealer()
    opened = values.Opened()
    owners: dict[str, list[Subject]] = {}
    try:
        for chunk in batched(subjects, LINES_A_QUERY):
            sealed = db.execute(
                select(Finding.id, Finding.match_sealed).where(Finding.id.in_(chunk))
            )
            for finding_id, blob in sealed:
                opened.take(blob)
                matched = sealer.open(blob, Purpose.FINDING_MATCH).decode("utf-8", "replace")
                line = clean_file_text(matched).strip(LINE_STRIP)
                if len(line) < known.ANCHOR_CHARS:
                    continue
                held = owners.setdefault(line, [])
                if subjects[finding_id] not in held:
                    held.append(subjects[finding_id])
    except values.TooManyToDecrypt:
        return _Lines(owners, unchecked=True)
    return _Lines(owners, unchecked=False)


def _line_marks(text: str, lines: _Lines) -> tuple[known.Marked, bool]:
    if not lines.owners:
        return known.Marked((), truncated=False), lines.unchecked
    try:
        return known.mark(known.ValueFinder(lines.owners), text), lines.unchecked
    except values.TooManyToDecrypt:
        return known.Marked((), truncated=False), True


def _line_numbers(text: str, places: Collection[int]) -> dict[int, int]:
    numbers: dict[int, int] = {}
    line = 1
    counted = 0
    for place in sorted(set(places)):
        line += text.count("\n", counted, place)
        counted = place
        numbers[place] = line
    return numbers


def _first_found(recorded: Sequence[_Recorded], commit: str) -> dict[Subject, FirstFoundOut | None]:
    earliest: dict[Subject, _Recorded] = {}
    here: set[Subject] = set()
    for each in recorded:
        if each.commit == commit:
            here.add(each.subject)
            continue
        known_first = earliest.get(each.subject)
        if known_first is None or _found_order(each) < _found_order(known_first):
            earliest[each.subject] = each
    return {
        subject: None
        if subject in here
        else FirstFoundOut(commit=earliest[subject].commit, line=earliest[subject].line)
        for subject in {*here, *earliest}
    }


def _found_order(each: _Recorded) -> tuple[bool, datetime, int]:
    return each.authored_at is None, each.authored_at or _NO_DATE, each.finding_id


def _recorded_here(recorded: Sequence[_Recorded], commit: str) -> dict[Subject, int | None]:
    lines: dict[Subject, int | None] = {}
    for each in recorded:
        if each.commit != commit:
            continue
        line = each.line if each.place is FindingPlace.LINE and each.line > 0 else None
        was = lines.get(each.subject)
        if each.subject not in lines or (line is not None and (was is None or line < was)):
            lines[each.subject] = line
    return lines


def _shown_values(
    db: Session, subjects: Sequence[Subject], shown_known: Mapping[Subject, str]
) -> dict[Subject, str]:
    shown = {subject: shown_known[subject] for subject in subjects if subject in shown_known}
    missing = [subject for subject in subjects if subject not in shown]
    sealer = app_sealer()
    for chunk in batched(missing, VALUES_A_QUERY):
        try:
            opened = values.values_of(db, sealer, list(chunk), opened=values.Opened())
        except (values.TooManyToDecrypt, NoSuchSubject):
            continue
        shown.update(as_in_files(opened))
    return shown


@dataclass(frozen=True)
class _Listed:
    subjects: list[MarkedSubjectOut]
    cut: bool
    seen: int
    unchecked: bool


def _listed(
    text: str,
    places: Mapping[Subject, int],
    here: Mapping[Subject, int | None],
    first_found: Mapping[Subject, FirstFoundOut | None],
    shown_known: Mapping[Subject, str],
) -> _Listed:
    in_text = sorted(places, key=lambda s: (places[s], s.kind is not SubjectKind.SECRET, s.id))
    rest = sorted(
        (subject for subject in here if subject not in places),
        key=lambda s: (here[s] is None, here[s] or 0, s.id),
    )
    ordered = [*in_text, *rest]
    cut = len(ordered) > MAX_FILE_SUBJECTS
    ordered = ordered[:MAX_FILE_SUBJECTS]
    numbers = _line_numbers(text, [places[s] for s in ordered if s in places])
    with read_phase() as db:
        described = classify.described(db, ordered)
        listed = [subject for subject in ordered if subject in described]
        shown = _shown_values(db, listed, shown_known)
        seen = latest_change_id(db)
        possible, unchecked = possible_canaries(db, app_sealer(), listed, values.Opened())
    subjects = [
        MarkedSubjectOut(
            key=subject_key(subject),
            kind=subject.kind,
            id=subject.id,
            type=described[subject][0],
            status=described[subject][1],
            value=value[:SUBJECT_VALUE_SHOWN],
            value_cut=len(value) > SUBJECT_VALUE_SHOWN,
            possible_canary=subject in possible,
            line=numbers[places[subject]] if subject in places else here.get(subject),
            in_text=subject in places,
            first_found=first_found.get(subject),
        )
        for subject in listed
        if (value := shown.get(subject)) is not None
    ]
    return _Listed(subjects, cut, seen, unchecked)


@bp.post(f"{REPOSITORY}/explore/file", endpoint="file")
@require_role(VALUES_ROLE)
@bp.input(FileIn, arg_name="body")
@bp.output(FileOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: REPOSITORY_404,
        422: "A commit or path out of its bounds",
        503: SCANNING_503,
    }
)
def explore_file(id: int, body: FileIn) -> FileOut:
    path = body.segments()
    done: _Read[FileContent] = _explore(
        id,
        lambda at: trees.read_file(at.runner, at.git_dir, body.commit, path, deadline=at.deadline),
        known_as=as_in_files,
        commit=body.commit,
        version=body.version,
    )
    if isinstance(done.found, Unavailable):
        return FileOut(_unavailable(done.found))
    content = done.found
    text = content.text or ""
    dropped = done.marks_dropped
    try:
        marked = known.mark(done.index, text)
    except values.TooManyToDecrypt:
        marked, dropped = known.Marked((), truncated=False), True
    value_owners = _owners(done.known)
    places: dict[Subject, int] = {}
    for value, start in marked.found.items():
        owner = value_owners.get(value)
        if owner is not None and (owner not in places or start < places[owner]):
            places[owner] = start
    recorded: list[_Recorded] = []
    lines = _Lines({}, unchecked=False)
    if content.text is not None:
        with read_phase() as db:
            recorded, too_many = _recorded(db, id, body.commit, b"/".join(path))
            candidates = {each.subject for each in recorded if each.subject not in places}
            lines = _recorded_lines(db, recorded, candidates)
        if too_many:
            lines = _Lines(lines.owners, unchecked=True)
    line_marked, lines_unchecked = _line_marks(text, lines)
    line_owners: dict[str, Subject] = {}
    for line, start in line_marked.found.items():
        held = lines.owners[line]
        line_owners[line] = held[0]
        for subject in held:
            if subject not in places or start < places[subject]:
                places[subject] = start
    marks = known.merged_marks(marked, line_marked)
    listed = _listed(
        text,
        places,
        _recorded_here(recorded, body.commit),
        _first_found(recorded, body.commit),
        done.known,
    )
    return FileOut(
        FileShownOut(
            text=content.text,
            binary=content.binary,
            too_large=content.too_large,
            size=content.size,
            integrity_failed=done.integrity_failed,
            marks=_marks_out(text, marks, ChainMap(value_owners, line_owners)),
            marks_truncated=marks.truncated,
            marks_dropped=dropped,
            subjects=listed.subjects,
            subjects_cut=listed.cut,
            lines_unchecked=lines_unchecked,
            last_change_id=listed.seen,
            canary_unchecked=listed.unchecked,
        )
    )


@bp.post(f"{REPOSITORY}/explore/search", endpoint="search")
@require_role(VALUES_ROLE)
@bp.input(SearchIn, arg_name="body")
@bp.output(SearchOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: REPOSITORY_404,
        422: "A commit, query or folder out of its bounds",
        503: SCANNING_503,
    }
)
def explore_search(id: int, body: SearchIn) -> SearchOut:
    folder = body.folder_segments()

    def read(at: _At) -> SearchResult | Unavailable:
        return search.find_content(
            at.runner, at.git_dir, body.commit, body.query, folder=folder, deadline=at.deadline
        )

    done = _explore(id, read, commit=body.commit, version=body.version)
    if isinstance(done.found, Unavailable):
        return SearchOut(_unavailable(done.found))
    result = done.found
    hits = []
    for hit in result.hits:
        offsets = utf16_offsets(hit.text, (hit.start, hit.end))
        hits.append(
            LineHitOut(
                path=[segment_out(part) for part in hit.path],
                line=hit.number,
                text=hit.text,
                start=offsets[hit.start],
                end=offsets[hit.end],
                cut=hit.cut,
            )
        )
    return SearchOut(
        SearchHitsOut(
            hits=hits,
            files=result.files,
            skipped_large=result.skipped_large,
            skipped_binary=result.skipped_binary,
            cut=result.cut,
        )
    )


def _holding_findings(repository_id: int, commit_ids: list[str]) -> frozenset[str]:
    if not commit_ids:
        return frozenset()
    with read_phase() as db:
        named = db.scalars(
            select(Finding.commit)
            .where(Finding.repository_id == repository_id, Finding.commit.in_(commit_ids))
            .distinct()
        )
        return frozenset(named)


@bp.post(f"{REPOSITORY}/history", endpoint="history")
@require_role(VALUES_ROLE)
@bp.input(HistoryIn, arg_name="body")
@bp.output(ExplorerHistoryOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: REPOSITORY_404,
        422: "A skip or query out of its bounds",
        503: SCANNING_503,
    }
)
def explore_history(id: int, body: HistoryIn) -> ExplorerHistoryOut:
    done: _Read[HistoryPage] = _explore(
        id,
        lambda at: commits.history_page(
            at.runner, at.git_dir, skip=body.skip, query=body.query, deadline=at.deadline
        ),
        known_as=_as_stored,
        version=body.version,
    )
    if isinstance(done.found, Unavailable):
        return ExplorerHistoryOut(_unavailable(done.found))
    page = done.found
    size = sum(len(row.message) for row in page.rows)
    dropped = done.marks_dropped
    try:
        found = [list(done.index.occurrences(row.message, size=size)) for row in page.rows]
    except values.TooManyToDecrypt:
        found, dropped = [[] for _ in page.rows], True
    holding = _holding_findings(id, [row.id for row in page.rows])
    rows = []
    for row, spans in zip(page.rows, found, strict=True):
        subject, cut = known.marked_subject(row.message, spans)
        rows.append(
            HistoryRowOut(
                id=row.id,
                parents=list(row.parents),
                author=_ident_out(row.author),
                subject=message_line(subject),
                subject_cut=cut,
                too_large=row.too_large,
                holds_findings=row.id in holding,
            )
        )
    return ExplorerHistoryOut(
        HistoryPageOut(
            rows=rows,
            next_skip=page.next_skip,
            scanned=page.scanned,
            cut=page.cut,
            unread=page.unread,
            marks_dropped=dropped,
        )
    )
