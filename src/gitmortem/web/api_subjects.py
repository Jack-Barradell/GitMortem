from collections.abc import Callable, Sequence
from typing import Any, NoReturn

from apiflask import APIBlueprint, abort
from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.config import guarded_key_file
from gitmortem.db.models import Finding, Repository, Role
from gitmortem.triage import classify, context, detail, footprint, notes, values
from gitmortem.triage.context import Context, Message, Segment, Unavailable
from gitmortem.triage.detail import FindingView, NoSuchFinding
from gitmortem.triage.notes import NoteView
from gitmortem.triage.query import latest_change_id
from gitmortem.triage.subjects import NoSuchSubject, Subject, SubjectKind
from gitmortem.triage.values import TooManyToDecrypt
from gitmortem.web.actors import current_actor
from gitmortem.web.api_triage import NO_SUCH_SUBJECT, VALUES_ROLE
from gitmortem.web.canary_check import subject_hints
from gitmortem.web.dbsession import get_db, read_phase
from gitmortem.web.scans import running_scans
from gitmortem.web.sealing import app_sealer
from gitmortem.web.security import client_ip, now, require_role
from gitmortem.web.triage_schemas import (
    CanaryHintOut,
    ContextLineOut,
    ContextLinesOut,
    ContextOut,
    ContextUnavailableOut,
    FindingItemOut,
    FindingOut,
    FindingPageOut,
    FindingsQueryIn,
    FirstSeenOut,
    FootprintPageQueryIn,
    FootprintPlaceOut,
    FootprintPlacePageOut,
    FootprintPlacesQueryIn,
    FootprintRepositoryOut,
    FootprintRepositoryPageOut,
    HistoryEntryOut,
    HistoryOut,
    MarkedSegmentOut,
    MessageLineOut,
    NoteDeleteIn,
    NoteEditIn,
    NoteIn,
    NoteListOut,
    NoteOut,
    PlaceFindingsQueryIn,
    SecretOut,
)

bp = APIBlueprint("subjects", __name__, url_prefix="/api")
ID = "<id:id>"
PREFIXES = {"secrets": SubjectKind.SECRET, "findings": SubjectKind.FINDING}
NO_SUCH_NOTE = "No such note."
NOTE_CHANGED = (
    "The note changed since it was read (`detail.reason` `note_changed`, naming who changed it"
    " and when); nothing was written"
)
NO_SUCH_SECRET = "No such secret."  # noqa: S105
NO_SUCH_FINDING = "No such finding."
SUBJECT_404 = "A subject that is not there, or a finding that has a secret"
VALUES_403 = "A user who may not see values; nothing was read"
VALUE_422 = "A value too large to send, or more values than one request may open; nothing shown"
NOT_ITS_FINDING = "This secret has no such finding."


def _per_kind[V: Callable[..., Any]](method: str, suffix: str, endpoint: str) -> Callable[[V], V]:
    def register(view: V) -> V:
        for prefix, kind in PREFIXES.items():
            bp.route(
                f"/{prefix}/{ID}{suffix}",
                methods=[method],
                endpoint=endpoint,
                defaults={"kind": kind},
            )(view)
        return view

    return register


def _note_out(view: NoteView) -> NoteOut:
    return NoteOut(
        id=view.id,
        text=view.text,
        author=view.author,
        created_at=view.created_at,
        edited_by=view.edited_by,
        edited_at=view.edited_at,
        version=view.version,
    )


def _note_changed(changed: notes.NoteChanged) -> NoReturn:
    get_db().rollback()
    abort(
        409,
        message=str(changed),
        detail={
            "reason": changed.REASON,
            "edited_by": changed.edited_by,
            "edited_at": None if changed.edited_at is None else changed.edited_at.isoformat(),
        },
    )


@_per_kind("GET", "/history", "history")
@require_role(Role.ANALYST)
@bp.output(HistoryOut)
@bp.doc(responses={404: SUBJECT_404})
def subject_history(kind: SubjectKind, id: int) -> HistoryOut:
    try:
        entries = classify.history(get_db(), Subject(kind, id))
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SUBJECT)
    return HistoryOut(
        items=[
            HistoryEntryOut(
                at=entry.at,
                user=entry.user,
                from_status=entry.from_status,
                to_status=entry.to_status,
                batch_id=entry.batch_id,
            )
            for entry in entries
        ]
    )


@_per_kind("GET", "/notes", "notes")
@require_role(Role.ANALYST)
@bp.output(NoteListOut)
@bp.doc(responses={404: SUBJECT_404, 422: "More notes than one request may open."})
def subject_notes(kind: SubjectKind, id: int) -> NoteListOut:
    try:
        found = notes.notes_of(get_db(), app_sealer(), Subject(kind, id))
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SUBJECT)
    except values.TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    return NoteListOut(items=[_note_out(view) for view in found])


@_per_kind("POST", "/notes", "add_note")
@require_role(Role.ANALYST)
@bp.input(NoteIn, arg_name="body")
@bp.output(NoteOut, status_code=201)
@bp.doc(responses={404: f"{SUBJECT_404}; nothing was written", 422: "An empty or long note"})
def add_note(kind: SubjectKind, id: int, body: NoteIn) -> tuple[NoteOut, int]:
    db, sealer, actor = get_db(), app_sealer(), current_actor()
    try:
        note = notes.add_note(db, sealer, Subject(kind, id), body.text, user=actor, now=now())
    except NoSuchSubject:
        db.rollback()
        abort(404, message=NO_SUCH_SUBJECT)
    return _note_out(notes.view_note(db, sealer, note)), 201


@bp.patch(f"/notes/{ID}", endpoint="edit_note")
@require_role(Role.ANALYST)
@bp.input(NoteEditIn, arg_name="body")
@bp.output(NoteOut)
@bp.doc(responses={404: NO_SUCH_NOTE, 409: NOTE_CHANGED, 422: "An empty or long note"})
def edit_note(id: int, body: NoteEditIn) -> NoteOut:
    db, sealer, actor = get_db(), app_sealer(), current_actor()
    try:
        note = notes.edit_note(
            db, sealer, id, body.text, user=actor, now=now(), seen_version=body.version
        )
    except notes.NoSuchNote:
        db.rollback()
        abort(404, message=NO_SUCH_NOTE)
    except notes.NoteChanged as changed:
        _note_changed(changed)
    audit.record(
        db,
        AuditAction.NOTE_EDITED,
        actor=actor,
        ip=client_ip(),
        detail={"note_id": note.id},
        subjects=[notes.subject_of(note)],
    )
    return _note_out(notes.view_note(db, sealer, note))


@bp.post(f"/notes/{ID}/delete", endpoint="delete_note")
@require_role(Role.ANALYST)
@bp.input(NoteDeleteIn, arg_name="body")
@bp.doc(
    responses={
        204: "Deleted; audited without its text",
        404: NO_SUCH_NOTE,
        409: NOTE_CHANGED,
    }
)
def delete_note(id: int, body: NoteDeleteIn) -> tuple[str, int]:
    db = get_db()
    try:
        subject, author = notes.delete_note(db, id, seen_version=body.version)
    except notes.NoSuchNote:
        db.rollback()
        abort(404, message=NO_SUCH_NOTE)
    except notes.NoteChanged as changed:
        _note_changed(changed)
    audit.record(
        db,
        AuditAction.NOTE_DELETED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"note_id": id, "author_user_id": author},
        subjects=[subject],
    )
    return "", 204


def _segment_out(segment: Segment) -> MarkedSegmentOut:
    return MarkedSegmentOut(text=segment.text, mark=segment.mark)


def message_line(segments: Sequence[Segment]) -> MessageLineOut:
    return MessageLineOut(segments=[_segment_out(segment) for segment in segments])


def _item_fields(view: FindingView, message: Message | None) -> dict[str, Any]:
    fields = {
        name: getattr(view, name)
        for name in FindingItemOut.model_fields
        if name != "commit_message"
    }
    fields["commit_message"] = (
        None if message is None else [message_line(line) for line in message.lines]
    )
    return fields


def _subject_of(view: FindingView) -> Subject:
    if view.secret_id is None:
        return Subject(SubjectKind.FINDING, view.id)
    return Subject(SubjectKind.SECRET, view.secret_id)


@bp.get(f"/secrets/{ID}", endpoint="secret")
@require_role(VALUES_ROLE)
@bp.output(SecretOut)
@bp.doc(responses={403: VALUES_403, 404: NO_SUCH_SECRET, 422: VALUE_422})
def secret_detail(id: int) -> SecretOut:
    subject = Subject(SubjectKind.SECRET, id)
    try:
        with read_phase() as db:
            found = detail.secret_detail(db, id)
            value = values.value_of(db, app_sealer(), subject)
            first = found.first_seen
            marked = context.mark_messages(db, app_sealer(), [] if first is None else [first])
            hints, more, unchecked = _canary_out(db, subject)
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SECRET)
    except TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    message = marked.messages[0] if marked.messages else None
    return SecretOut(
        id=found.id,
        kind=found.kind,
        status=found.status,
        value=value,
        tools=list(found.tools),
        first_seen=None
        if first is None
        else FirstSeenOut(
            finding_id=first.id,
            repository_id=first.repository_id,
            repo=first.repo,
            display_path=first.display_path,
            line=first.line,
            commit=first.commit,
            authored_at=first.authored_at,
            author_name=first.author_name,
            author_email=first.author_email,
            message_subject=None if message is None else message_line(message.subject),
        ),
        findings=found.findings,
        repos=found.repos,
        last_change_id=found.last_change_id,
        marks_dropped=marked.marks_dropped,
        canary_hints=hints,
        canary_hints_more=more,
        canary_unchecked=unchecked,
    )


def _canary_out(db: Session, subject: Subject) -> tuple[list[CanaryHintOut], bool, bool]:
    hints, more, unchecked = subject_hints(db, app_sealer(), subject)
    ids = sorted({hint.finding_id for hint in hints})
    where = {
        finding_id: (repository_id, repo, commit, path)
        for finding_id, repository_id, repo, commit, path in db.execute(
            select(
                Finding.id,
                Finding.repository_id,
                Repository.display_path,
                Finding.commit,
                Finding.display_path,
            )
            .join(Repository, Finding.repository_id == Repository.id)
            .where(Finding.id.in_(ids))
        )
    }
    return (
        [
            CanaryHintOut(
                finding_id=hint.finding_id,
                repository_id=where[hint.finding_id][0],
                repo=where[hint.finding_id][1],
                commit=where[hint.finding_id][2],
                display_path=where[hint.finding_id][3],
                field=hint.field,
                word=hint.word,
            )
            for hint in hints
        ],
        more,
        unchecked,
    )


@bp.get(f"/secrets/{ID}/findings", endpoint="secret_findings")
@require_role(VALUES_ROLE)
@bp.input(FindingsQueryIn, location="query", arg_name="page_query")
@bp.output(FindingPageOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: f"{NO_SUCH_SECRET} Or, with a finding named, one that is not the secret's",
        422: "A query out of its bounds",
    }
)
def secret_findings(id: int, page_query: FindingsQueryIn) -> FindingPageOut:
    page = page_query.page
    try:
        with read_phase() as db:
            if page_query.finding is not None:
                page = detail.page_holding(db, id, page_query.finding, per_page=page_query.per_page)
            views, total = detail.secret_findings(db, id, page=page, per_page=page_query.per_page)
            marked = context.mark_messages(db, app_sealer(), views)
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SECRET)
    except NoSuchFinding:
        abort(404, message=NOT_ITS_FINDING)
    return FindingPageOut(
        items=[
            FindingItemOut(**_item_fields(view, message))
            for view, message in zip(views, marked.messages, strict=True)
        ],
        page=page,
        per_page=page_query.per_page,
        total=total,
        marks_dropped=marked.marks_dropped,
    )


@bp.get(f"/secrets/{ID}/places", endpoint="secret_places")
@require_role(VALUES_ROLE)
@bp.input(FootprintPlacesQueryIn, location="query", arg_name="page_query")
@bp.output(FootprintPlacePageOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: f"{NO_SUCH_SECRET} Or, with a finding named, one that is not the secret's",
        422: "A query out of its bounds",
    }
)
def secret_places(id: int, page_query: FootprintPlacesQueryIn) -> FootprintPlacePageOut:
    try:
        with read_phase() as db:
            found = footprint.places_page(
                db,
                id,
                page=page_query.page,
                per_page=page_query.per_page,
                finding=page_query.finding,
            )
            views = footprint.views_of(found)
            marked = context.mark_messages(db, app_sealer(), views)
            messages = dict(zip((view.id for view in views), marked.messages, strict=True))
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SECRET)
    except NoSuchFinding:
        abort(404, message=NOT_ITS_FINDING)
    return FootprintPlacePageOut(
        items=[
            FootprintPlaceOut(
                handle=place.handle,
                repository_id=place.repository_id,
                repo=place.repo,
                org=place.org,
                repository_on_disk=place.repository_on_disk,
                commit=place.commit,
                display_path=place.display_path,
                place=place.place,
                line=place.line,
                tools=list(place.tools),
                findings_total=place.findings_total,
                findings=[
                    FindingItemOut(**_item_fields(view, messages[view.id]))
                    for view in place.findings
                ],
                no_longer_reported=place.no_longer_reported,
                reported_live=place.reported_live,
                first_authored_at=place.first_authored_at,
            )
            for place in found.items
        ],
        page=found.page,
        per_page=found.per_page,
        total=found.total,
        holding=found.holding,
        marks_dropped=marked.marks_dropped,
    )


@bp.get(f"/secrets/{ID}/places/<id:handle>/findings", endpoint="place_findings")
@require_role(VALUES_ROLE)
@bp.input(PlaceFindingsQueryIn, location="query", arg_name="page_query")
@bp.output(FindingPageOut)
@bp.doc(
    responses={
        403: VALUES_403,
        404: f"{NO_SUCH_SECRET} Or a place that is not the secret's",
        422: "A query out of its bounds",
    }
)
def place_findings(id: int, handle: int, page_query: PlaceFindingsQueryIn) -> FindingPageOut:
    try:
        with read_phase() as db:
            found = footprint.place_findings(
                db,
                id,
                handle,
                page=page_query.page,
                per_page=page_query.per_page,
                skip=page_query.skip,
            )
            marked = context.mark_messages(db, app_sealer(), found.items)
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SECRET)
    except NoSuchFinding:
        abort(404, message=NOT_ITS_FINDING)
    return FindingPageOut(
        items=[
            FindingItemOut(**_item_fields(view, message))
            for view, message in zip(found.items, marked.messages, strict=True)
        ],
        page=found.page,
        per_page=found.per_page,
        total=found.total,
        marks_dropped=marked.marks_dropped,
    )


@bp.get(f"/secrets/{ID}/repositories", endpoint="secret_repositories")
@require_role(Role.ANALYST)
@bp.input(FootprintPageQueryIn, location="query", arg_name="page_query")
@bp.output(FootprintRepositoryPageOut)
@bp.doc(responses={404: NO_SUCH_SECRET, 422: "A query out of its bounds"})
def secret_repositories(id: int, page_query: FootprintPageQueryIn) -> FootprintRepositoryPageOut:
    try:
        with read_phase() as db:
            found = footprint.repositories_page(
                db, id, page=page_query.page, per_page=page_query.per_page
            )
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SECRET)
    return FootprintRepositoryPageOut(
        items=[
            FootprintRepositoryOut(
                repository_id=row.repository_id,
                repo=row.repo,
                org=row.org,
                repository_on_disk=row.repository_on_disk,
                places=row.places,
                findings=row.findings,
                first_authored_at=row.first_authored_at,
                last_authored_at=row.last_authored_at,
            )
            for row in found.items
        ],
        page=found.page,
        per_page=found.per_page,
        total=found.total,
    )


@bp.get(f"/findings/{ID}", endpoint="finding")
@require_role(VALUES_ROLE)
@bp.output(FindingOut)
@bp.doc(responses={403: VALUES_403, 404: NO_SUCH_FINDING, 422: VALUE_422})
def finding_detail(id: int) -> FindingOut:
    try:
        with read_phase() as db:
            view = detail.finding_view(db, id)
            value = values.value_of(db, app_sealer(), _subject_of(view))
            marked = context.mark_messages(db, app_sealer(), [view])
            standalone = view.secret_id is None
            last_change_id = latest_change_id(db) if standalone else None
            hints, more, unchecked = _canary_out(db, _subject_of(view))
    except NoSuchFinding:
        abort(404, message=NO_SUCH_FINDING)
    except TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    [message] = marked.messages
    return FindingOut(
        **_item_fields(view, message),
        secret_id=view.secret_id,
        status=view.status,
        last_change_id=last_change_id,
        value=value,
        marks_dropped=marked.marks_dropped,
        canary_hints=hints,
        canary_hints_more=more,
        canary_unchecked=unchecked,
    )


def _context_out(found: Context | Unavailable) -> ContextOut:
    if isinstance(found, Unavailable):
        return ContextOut(ContextUnavailableOut(unavailable=found))
    return ContextOut(
        ContextLinesOut(
            lines=[
                ContextLineOut(
                    number=line.number,
                    segments=[_segment_out(segment) for segment in line.segments],
                    is_match=line.is_match,
                    cut=line.cut,
                )
                for line in found.lines
            ],
            integrity_failed=found.integrity_failed,
            marks_dropped=found.marks_dropped,
        )
    )


@bp.get(f"/findings/{ID}/context", endpoint="context")
@require_role(VALUES_ROLE)
@bp.output(ContextOut)
@bp.doc(responses={403: VALUES_403, 404: NO_SUCH_FINDING, 503: "Scanning is not running"})
def finding_context(id: int) -> ContextOut:
    service = running_scans()
    try:
        with read_phase() as db:
            plan = context.plan_context(db, app_sealer(), id)
    except NoSuchFinding:
        abort(404, message=NO_SUCH_FINDING)
    if isinstance(plan, Unavailable):
        return _context_out(plan)
    settings = service.settings
    found = context.read_context(
        service.runner,
        plan,
        bases=settings.scan_root_bases,
        data_dir=settings.data_dir,
        key_file=guarded_key_file(settings),
        timeout=context.CONTEXT_GIT_SECONDS,
    )
    return _context_out(found)
