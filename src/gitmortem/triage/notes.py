from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import datetime
from typing import cast

from sqlalchemy import bindparam, select
from sqlalchemy.orm import Session, aliased

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import Note, User
from gitmortem.triage import values
from gitmortem.triage.subjects import Subject, SubjectKind, columns, require

MAX_NOTE_CHARS = 10_000


class NoSuchNote(LookupError):
    def __init__(self, note_id: int) -> None:
        super().__init__(f"no note {note_id}")
        self.note_id = note_id


class NoteChanged(ValueError):
    REASON = "note_changed"

    def __init__(self, edited_by: str | None, edited_at: datetime | None) -> None:
        self.edited_by = edited_by
        self.edited_at = edited_at
        super().__init__("This note changed since it was read: read it again before changing it.")


@dataclass(frozen=True)
class NoteView:
    id: int
    text: str = field(repr=False)
    author: str | None
    created_at: datetime
    edited_by: str | None
    edited_at: datetime | None
    version: int = 0


def clean_text(text: str) -> str:
    kept = text.rstrip()
    if not 1 <= len(kept) <= MAX_NOTE_CHARS:
        raise ValueError(f"a note needs 1 to {MAX_NOTE_CHARS} characters")
    try:
        kept.encode()
    except UnicodeEncodeError:
        raise ValueError("a note must be Unicode text") from None
    return kept


def _sealed(sealer: Sealer, text: str) -> bytes:
    return sealer.seal(clean_text(text).encode(), Purpose.NOTE_TEXT)


def subject_of(note: Note) -> Subject:
    if note.secret_id is not None:
        return Subject(SubjectKind.SECRET, note.secret_id)
    if note.finding_id is not None:
        return Subject(SubjectKind.FINDING, note.finding_id)
    raise ValueError(f"note {note.id} names no subject")


def add_note(
    session: Session, sealer: Sealer, subject: Subject, text: str, *, user: User, now: datetime
) -> Note:
    blob = _sealed(sealer, text)
    require(session, subject)
    note = Note(**columns(subject), author_user_id=user.id, created_at=now, text_sealed=blob)
    session.add(note)
    session.flush()
    return note


def _note(session: Session, note_id: int) -> Note:
    note = session.get(Note, note_id)
    if note is None:
        raise NoSuchNote(note_id)
    return note


def _unchanged(session: Session, note: Note, seen_version: int) -> None:
    if note.version != seen_version:
        raise NoteChanged(_username(session, note.edited_by_user_id), note.edited_at)


def edit_note(
    session: Session,
    sealer: Sealer,
    note_id: int,
    text: str,
    *,
    user: User,
    now: datetime,
    seen_version: int,
) -> Note:
    blob = _sealed(sealer, text)
    note = _note(session, note_id)
    _unchanged(session, note, seen_version)
    note.text_sealed = blob
    note.edited_by_user_id = user.id
    note.edited_at = now
    note.version += 1
    session.flush()
    return note


def delete_note(session: Session, note_id: int, *, seen_version: int) -> tuple[Subject, int | None]:
    note = _note(session, note_id)
    _unchanged(session, note, seen_version)
    subject, author = subject_of(note), note.author_user_id
    session.delete(note)
    session.flush()
    return subject, author


def _opened(sealer: Sealer, blob: bytes) -> str:
    return sealer.open(blob, Purpose.NOTE_TEXT).decode()


def _username(session: Session, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    return session.scalar(select(User.username).where(User.id == user_id))


def view_note(session: Session, sealer: Sealer, note: Note) -> NoteView:
    return NoteView(
        id=note.id,
        text=_opened(sealer, note.text_sealed),
        author=_username(session, note.author_user_id),
        created_at=note.created_at,
        edited_by=_username(session, note.edited_by_user_id),
        edited_at=note.edited_at,
        version=note.version,
    )


def notes_for(
    session: Session,
    sealer: Sealer,
    subjects: Collection[Subject],
    *,
    opened: values.Opened,
) -> dict[Subject, list[NoteView]]:
    secrets = sorted({s.id for s in subjects if s.kind is SubjectKind.SECRET})
    findings = sorted({s.id for s in subjects if s.kind is SubjectKind.FINDING})
    author, editor = aliased(User), aliased(User)
    found: dict[Subject, list[NoteView]] = {}
    for kind, column, ids in (
        (SubjectKind.SECRET, Note.secret_id, secrets),
        (SubjectKind.FINDING, Note.finding_id, findings),
    ):
        if not ids:
            continue
        rows = session.execute(
            select(
                column,
                Note.id,
                Note.text_sealed,
                author.username,
                Note.created_at,
                editor.username,
                Note.edited_at,
            )
            .outerjoin(author, author.id == Note.author_user_id)
            .outerjoin(editor, editor.id == Note.edited_by_user_id)
            .where(column.in_(bindparam("ids", ids, expanding=True, literal_execute=True)))
            .order_by(Note.created_at, Note.id)
        ).all()
        opened.reserve(len(rows))
        for owner, note_id, blob, written_by, created_at, edited_by, edited_at in rows:
            opened.take(blob)
            found.setdefault(Subject(kind, cast(int, owner)), []).append(
                NoteView(
                    id=note_id,
                    text=_opened(sealer, blob),
                    author=written_by,
                    created_at=created_at,
                    edited_by=edited_by,
                    edited_at=edited_at,
                )
            )
    return found


def notes_of(
    session: Session, sealer: Sealer, subject: Subject, *, opened: values.Opened | None = None
) -> list[NoteView]:
    require(session, subject)
    request = values.Opened() if opened is None else opened
    author, editor = aliased(User), aliased(User)
    on = Note.secret_id if subject.kind is SubjectKind.SECRET else Note.finding_id
    found = session.execute(
        select(
            Note.id,
            Note.text_sealed,
            author.username,
            Note.created_at,
            editor.username,
            Note.edited_at,
            Note.version,
        )
        .outerjoin(author, author.id == Note.author_user_id)
        .outerjoin(editor, editor.id == Note.edited_by_user_id)
        .where(on == subject.id)
        .order_by(Note.created_at, Note.id)
    )
    shown: list[NoteView] = []
    for note_id, blob, written_by, created_at, edited_by, edited_at, version in found:
        request.reserve(1)
        request.take(blob)
        shown.append(
            NoteView(
                id=note_id,
                text=_opened(sealer, blob),
                author=written_by,
                created_at=created_at,
                edited_by=edited_by,
                edited_at=edited_at,
                version=version,
            )
        )
    return shown
