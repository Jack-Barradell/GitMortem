import io
import json
from collections import defaultdict
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from gitmortem.crypto import Sealer
from gitmortem.db.models import Finding
from gitmortem.export import ExportFormat
from gitmortem.export.cells import clean, cut_to_units, neutral, shown, utf16_units
from gitmortem.export.formats import write_csv, write_json, write_txt
from gitmortem.export.xlsx import MAX_CELL_CHARS, SheetFull, XlsxBook
from gitmortem.triage import context, detail, notes, query, stats, values
from gitmortem.triage.detail import FindingView, message_of
from gitmortem.triage.known_values import MarkWork, ValueFinder, known_everywhere
from gitmortem.triage.notes import NoteView
from gitmortem.triage.query import Filters, ListSort, Order, Row, View
from gitmortem.triage.subjects import Subject

MAX_REPOSITORY_SHEETS = 250
EXPORT_MARK_WORK = 200_000_000
VALUE_MARKER = "[value]"
TOO_LONG = "(Too long for a spreadsheet cell: see the json or txt export.)"
_CUT = " … [cut]"
_CHUNK = 10_000
MAX_EXPORT_BYTES = 256 << 20


class ExportTooLarge(values.TooManyToDecrypt):
    MESSAGE = "This export is too large to build: narrow the list with filters first."


_UNIQUE_COLUMNS = (
    "Subject",
    "Type",
    "Status",
    "Value",
    "Findings",
    "Repositories",
    "Tools",
    "Org",
    "Repository",
    "Path",
    "Line",
    "Place",
    "Commit",
    "Authored",
    "Author",
    "Author email",
    "Message",
    "No longer reported",
    "Reported live",
    "Notes",
)
_ALL_COLUMNS = (
    "Subject",
    "Finding",
    "Type",
    "Status",
    "Value",
    "Repositories",
    "Tool",
    "Rule",
    "Org",
    "Repository",
    "Path",
    "Line",
    "Place",
    "Commit",
    "Authored",
    "Author",
    "Author email",
    "Message",
    "No longer reported",
    "Reported live",
    "Notes",
)


@dataclass(frozen=True)
class ExportRequest:
    filters: Filters
    view: View
    sort: ListSort
    order: Order
    only: Collection[Subject] | None
    format: ExportFormat
    include_values: bool
    text_filtered: bool


@dataclass(frozen=True)
class ExportFile:
    content: bytes = field(repr=False)
    media_type: str
    filename: str
    rows: int
    subjects: list[Subject]


@dataclass(frozen=True)
class _Line:
    subject: Subject
    repository: str
    cells: dict[str, str] = field(repr=False)
    notes: Sequence[NoteView] = field(repr=False, default=())


class _Mask:
    def __init__(self, finder: ValueFinder | None) -> None:
        self._finder = finder
        self._done: dict[str, str] = {}

    def __call__(self, text: str) -> str:
        if self._finder is None or not text:
            return text
        found = self._done.get(text)
        if found is None:
            found = self._done[text] = context.masked(text, self._finder, VALUE_MARKER)
        return found

    def message(self, text: str, *, cut: bool) -> str:
        if self._finder is None:
            return text
        return context.masked(text, self._finder, VALUE_MARKER, cut=cut)


_MASKED = ("Type", "Rule", "Org", "Repository", "Path", "Author", "Author email", "Notes")


def _subject_name(subject: Subject) -> str:
    return f"{subject.kind.value}:{subject.id}"


def _note_text(found: Sequence[NoteView]) -> str:
    return "\n\n".join(
        f"{note.created_at.isoformat()} {note.author or '-'}: {note.text}" for note in found
    )


def _rows(
    session: Session, sealer: Sealer, request: ExportRequest, opened: values.Opened
) -> list[Row]:
    if request.sort is ListSort.VALUE:
        subjects = query.matching_subjects(
            session, request.filters, view=View.UNIQUE, only=request.only
        )
        ordered = values.sort_by_value(session, sealer, subjects, request.order, opened=opened)
        return query.rows_for(session, request.filters, view=View.UNIQUE, subjects=ordered)
    return query.all_rows(
        session,
        request.filters,
        view=request.view,
        sort=request.sort,
        order=request.order,
        only=request.only,
    )


def _views(session: Session, ids: Collection[int]) -> dict[int, FindingView]:
    found: dict[int, FindingView] = {}
    ordered = sorted(ids)
    for start in range(0, len(ordered), _CHUNK):
        chunk = ordered[start : start + _CHUNK]
        for row in session.execute(detail._views(Finding.id.in_(chunk))):
            view = detail._view(row)
            found[view.id] = view
    return found


def _bounded(
    listed: Sequence[Row],
    views: dict[int, FindingView],
    elsewhere: dict[Subject, list[int]],
    held: dict[Subject, str],
    joined: dict[Subject, str],
    *,
    unique: bool,
) -> None:
    sizes: dict[Subject, int] = {}
    total = 0
    for row in listed:
        each = sizes.get(row.subject)
        if each is None:
            each = sizes[row.subject] = len(held.get(row.subject, "").encode()) + len(
                joined.get(row.subject, "").encode()
            )
        places = elsewhere.get(row.subject, []) if unique else []
        written = [row.anchor_finding_id, *(places or [row.anchor_finding_id])]
        total += each * len(written)
        for finding_id in written:
            sealed = views[finding_id].message_sealed
            total += 0 if sealed is None else len(sealed)
        if total > MAX_EXPORT_BYTES:
            raise ExportTooLarge


def build_export(
    session: Session, sealer: Sealer, request: ExportRequest, *, now: datetime
) -> ExportFile:
    opened = values.Opened()
    listed = _rows(session, sealer, request, opened)
    subjects = list(dict.fromkeys(row.subject for row in listed))
    unique = request.view is View.UNIQUE
    elsewhere: dict[Subject, list[int]] = defaultdict(list)
    if unique and listed:
        for subject, finding_id in query.first_places(session, request.filters, only=request.only):
            elsewhere[subject].append(finding_id)
    wanted = {row.anchor_finding_id for row in listed} | {
        finding_id for ids in elsewhere.values() for finding_id in ids
    }
    views = _views(session, wanted)
    mask = _Mask(None)
    redacted: dict[int, str] = {}
    if not request.include_values:
        known = known_everywhere(session, sealer, opened=opened)
        mask = _Mask(ValueFinder(known.values(), work=MarkWork(EXPORT_MARK_WORK)))
        redacted = {
            view.id: mask.message(message_of(sealer, view) or "", cut=view.message_cut)
            for view in views.values()
        }
    held = (
        values.values_of(session, sealer, subjects, opened=opened) if request.include_values else {}
    )
    written = notes.notes_for(session, sealer, subjects, opened=opened)
    joined = {subject: _note_text(found) for subject, found in written.items()}
    _bounded(listed, views, elsewhere, held, joined, unique=unique)
    summary = stats.stats(session, request.filters, view=request.view, only=request.only)

    def line(row: Row, view: FindingView) -> _Line:
        value = held.get(row.subject)
        cells = {
            "Subject": _subject_name(row.subject),
            "Finding": str(view.id),
            "Type": row.kind,
            "Status": row.status.value,
            "Value": "" if value is None else value,
            "Findings": str(row.findings),
            "Repositories": str(row.repos),
            "Tools": ", ".join(tool.value for tool in row.tools),
            "Tool": view.tool.value,
            "Rule": view.rule,
            "Org": view.org or "",
            "Repository": view.repo,
            "Path": "" if view.place.value == "message" else view.display_path,
            "Line": str(view.line),
            "Place": view.place.value,
            "Commit": view.commit,
            "Authored": "" if view.authored_at is None else view.authored_at.isoformat(),
            "Author": view.author_name,
            "Author email": view.author_email,
            "Message": (
                (message_of(sealer, view) or "")
                if request.include_values
                else redacted.get(view.id, "")
            ),
            "No longer reported": "yes" if view.no_longer_reported else "no",
            "Reported live": "yes" if view.reported_live else "no",
            "Notes": joined.get(row.subject, ""),
        }
        if unique:
            cells["No longer reported"] = "yes" if row.no_longer_reported else "no"
            cells["Reported live"] = "yes" if row.reported_live else "no"
        for name in _MASKED:
            if name in cells:
                cells[name] = mask(cells[name])
        for name in cells:
            if name != "Value":
                cells[name] = shown(cells[name])
        return _Line(
            subject=row.subject,
            repository=view.repo,
            cells=cells,
            notes=[
                replace(note, text=shown(mask(note.text))) for note in written.get(row.subject, [])
            ],
        )

    lines = [line(row, views[row.anchor_finding_id]) for row in listed]
    by_repository: dict[tuple[int, str], list[_Line]] = defaultdict(list)
    for row, made in zip(listed, lines, strict=True):
        if unique:
            for finding_id in elsewhere.get(row.subject, [row.anchor_finding_id]):
                view = views[finding_id]
                by_repository[(view.repository_id, shown(mask(view.repo)))].append(line(row, view))
        else:
            view = views[row.anchor_finding_id]
            by_repository[(view.repository_id, shown(mask(view.repo)))].append(made)
    columns = _UNIQUE_COLUMNS if unique else _ALL_COLUMNS
    preamble = _preamble(request, now, summary, mask)
    content = _write(request, columns, lines, by_repository, preamble, summary, mask)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return ExportFile(
        content=content,
        media_type=request.format.media_type,
        filename=f"gitmortem-export-{stamp}.{request.format.extension}",
        rows=len(lines),
        subjects=subjects,
    )


def _choices(filters: Filters, mask: "_Mask") -> dict[str, Any]:
    chosen: dict[str, Any] = {}
    for name, value in (
        ("orgs", list(filters.orgs)),
        ("no_org", filters.no_org),
        ("repository_ids", list(filters.repository_ids)),
        ("kinds", list(filters.kinds)),
        ("kinds_negated", filters.kinds_negated),
        ("tools", [tool.value for tool in filters.tools]),
        ("statuses", [status.value for status in filters.statuses]),
        ("statuses_negated", filters.statuses_negated),
        ("scan_id", filters.scan_id),
        ("reported", filters.reported.value),
        ("reported_live", filters.reported_live),
        ("reused", filters.reused),
    ):
        if value not in ([], None, False, "all"):
            chosen[name] = (
                [mask(item) if isinstance(item, str) else item for item in value]
                if (isinstance(value, list))
                else value
            )
    if filters.authored_from is not None:
        chosen["authored_from"] = filters.authored_from.isoformat()
    if filters.authored_to is not None:
        chosen["authored_to"] = filters.authored_to.isoformat()
    return chosen


def _preamble(
    request: ExportRequest, now: datetime, summary: stats.Stats, mask: "_Mask"
) -> list[str]:
    said = [
        "GitMortem export",
        f"Made: {now.isoformat()}",
        f"View: {request.view.value}",
        f"Filters: {shown(json.dumps(_choices(request.filters, mask), sort_keys=True))}",
        f"Totals: {summary.findings} findings, {summary.unique} unique",
        "Values: "
        + (
            "included, as stored"
            if request.include_values
            else f"none; each value GitMortem knows is written {VALUE_MARKER} in every cell"
        ),
    ]
    if request.text_filtered:
        said.append("A text filter applied (its text is not written here).")
    if request.only is not None:
        said.append("A value search applied (its text is not written here).")
    said.append(
        "Repository text and notes are as stored, with control and direction characters"
        " written as U+FFFD."
    )
    return said


def _summary_rows(summary: stats.Stats, mask: "_Mask") -> list[list[str]]:
    out = [["Findings", str(summary.findings)], ["Unique", str(summary.unique)], []]
    for dimension, groups in summary.dimensions.items():
        out.append([f"By {dimension.value}", "Findings", "Unique"])
        for group in groups.groups:
            key = group.label or (
                "No org" if group.key is None else str(getattr(group.key, "value", group.key))
            )
            out.append([shown(mask(key)), str(group.findings), str(group.unique)])
        if groups.total_groups > len(groups.groups):
            out.append([f"{groups.total_groups - len(groups.groups)} more not shown"])
        out.append([])
    return out


def _cell(text: str) -> str:
    return neutral(clean(text))


def _xlsx_cell(name: str, text: str) -> tuple[str, bool]:
    cell = _cell(text)
    if utf16_units(cell) <= MAX_CELL_CHARS:
        return cell, False
    if name == "Value":
        return TOO_LONG, True
    return cut_to_units(cell, MAX_CELL_CHARS - utf16_units(_CUT)) + _CUT, False


def _write(
    request: ExportRequest,
    columns: Sequence[str],
    lines: list[_Line],
    by_repository: dict[tuple[int, str], list[_Line]],
    preamble: list[str],
    summary: stats.Stats,
    mask: "_Mask",
) -> bytes:
    form = request.format
    if form is ExportFormat.CSV:
        text = io.StringIO()
        write_csv(columns, ([made.cells[name] for name in columns] for made in lines), text)
        return text.getvalue().encode("utf-8")
    if form is ExportFormat.JSON:
        text = io.StringIO()
        document = {
            "export": {"made": preamble[1].removeprefix("Made: "), "view": request.view.value},
            "filters": _choices(request.filters, mask),
            "text_filtered": request.text_filtered,
            "value_searched": request.only is not None,
            "include_values": request.include_values,
            "totals": {"findings": summary.findings, "unique": summary.unique},
            "rows": [_json_row(made, columns) for made in lines],
        }
        write_json(document, text)
        return text.getvalue().encode("utf-8")
    if form is ExportFormat.TXT:
        text = io.StringIO()
        groups = [
            (name, [[made.cells[column] for column in columns] for made in held])
            for (_, name), held in sorted(by_repository.items(), key=lambda item: item[0][1])
        ]
        write_txt(preamble, columns, groups, text)
        return text.getvalue().encode("utf-8")
    return _xlsx(columns, lines, by_repository, preamble, summary, mask)


def _json_row(made: _Line, columns: Sequence[str]) -> dict[str, Any]:
    row: dict[str, Any] = {
        name.lower().replace(" ", "_"): made.cells[name] for name in columns if name != "Notes"
    }
    row["notes"] = [
        {"author": note.author, "at": note.created_at.isoformat(), "text": note.text}
        for note in made.notes
    ]
    return row


def _xlsx(
    columns: Sequence[str],
    lines: list[_Line],
    by_repository: dict[tuple[int, str], list[_Line]],
    preamble: list[str],
    summary: stats.Stats,
    mask: "_Mask",
) -> bytes:
    out = io.BytesIO()
    too_long = 0
    repositories = sorted(by_repository.items(), key=lambda item: item[0][1])
    sheeted = repositories[:MAX_REPOSITORY_SHEETS]
    left = len(repositories) - len(sheeted)
    with XlsxBook(out) as book:
        for made in lines:
            for name in columns:
                if _xlsx_cell(name, made.cells[name])[1]:
                    too_long += 1
        top = book.sheet("Summary")
        for said in preamble:
            top.row([_xlsx_cell("Summary", said)[0]])
        top.row([])
        for row in _summary_rows(summary, mask):
            top.row([_xlsx_cell("Summary", cell)[0] for cell in row])
        if left:
            top.row(
                [
                    f"{left} repository has no sheet of its own"
                    if left == 1
                    else f"{left} repositories have no sheet of their own"
                ]
            )
        if too_long:
            top.row(
                [
                    f"{too_long} value was too long for a cell"
                    if too_long == 1
                    else f"{too_long} values were too long for a cell"
                ]
            )
        _rows_into(book, "All rows", columns, lines)
        for (_, name), held in sheeted:
            _rows_into(book, name, columns, held)
    return out.getvalue()


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _rows_into(book: XlsxBook, title: str, columns: Sequence[str], lines: list[_Line]) -> None:
    part = 1
    sheet = book.sheet(title)
    sheet.row(list(columns))
    for made in lines:
        cells = [_xlsx_cell(name, made.cells[name])[0] for name in columns]
        try:
            sheet.row(cells)
        except SheetFull:
            part += 1
            sheet = book.sheet(f"{title} ({part})")
            sheet.row(list(columns))
            sheet.row(cells)


__all__ = [
    "EXPORT_MARK_WORK",
    "MAX_REPOSITORY_SHEETS",
    "TOO_LONG",
    "VALUE_MARKER",
    "ExportFile",
    "ExportRequest",
    "build_export",
]
