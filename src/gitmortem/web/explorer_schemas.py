import base64
import binascii
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, RootModel, field_validator

from gitmortem.db.models import SecretStatus
from gitmortem.explorer.access import Unavailable
from gitmortem.explorer.commits import MAX_HISTORY_SKIP, RefKind
from gitmortem.explorer.search import MAX_QUERY_CHARS
from gitmortem.explorer.trees import MAX_PATH_BYTES, MAX_SEGMENT_BYTES, EntryKind, PathSegments
from gitmortem.triage.context import clean_line
from gitmortem.triage.subjects import SubjectKind
from gitmortem.web.triage_schemas import MessageLineOut

__all__ = [
    "MAX_SEGMENTS",
    "CommitOut",
    "FileIn",
    "FileOut",
    "FolderOut",
    "FullHex",
    "HeadOut",
    "HistoryIn",
    "NameHitsOut",
    "NamesIn",
    "PathSegment",
    "PlaceOut",
    "RefsOut",
    "SearchIn",
    "SearchOut",
    "TreeQueryIn",
    "segment_out",
    "shown",
    "shown_name",
    "spelled",
    "utf16_offsets",
]

MAX_SEGMENTS = 4_096
_MAX_SEGMENT_TEXT = (4 * MAX_SEGMENT_BYTES + 2) // 3
_MAX_PATH_TEXT = 4 * MAX_PATH_BYTES // 3 + 2 * MAX_SEGMENTS
_SEGMENT = f"a path segment is the base64url of 1 to {MAX_SEGMENT_BYTES} bytes, unpadded"
_PATH = f"a path has at most {MAX_SEGMENTS} segments, and {MAX_PATH_BYTES} bytes together"
_QUERY = "a query holds no line break or NUL"


def spelled(name: bytes) -> str:
    return base64.urlsafe_b64encode(name).rstrip(b"=").decode("ascii")


def _segment_bytes(text: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(_SEGMENT) from None
    if not 0 < len(raw) <= MAX_SEGMENT_BYTES or spelled(raw) != text:
        raise ValueError(_SEGMENT)
    return raw


def _checked_segment(text: str) -> str:
    _segment_bytes(text)
    return text


def _checked_path(segments: Sequence[str]) -> list[str]:
    if len(segments) > MAX_SEGMENTS:
        raise ValueError(_PATH)
    if sum(len(_segment_bytes(segment)) for segment in segments) > MAX_PATH_BYTES:
        raise ValueError(_PATH)
    return list(segments)


def _plain_query(query: str) -> str:
    if any(character in query for character in "\n\r\0"):
        raise ValueError(_QUERY)
    return query


def decoded(segments: Iterable[str]) -> PathSegments:
    return tuple(_segment_bytes(segment) for segment in segments)


FullHex = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
PathSegment = Annotated[
    str,
    Field(min_length=1, max_length=_MAX_SEGMENT_TEXT, pattern=r"^[A-Za-z0-9_-]+$"),
    AfterValidator(_checked_segment),
]
PathIn = Annotated[list[PathSegment], Field(max_length=MAX_SEGMENTS), AfterValidator(_checked_path)]
Query = Annotated[
    str, Field(min_length=1, max_length=MAX_QUERY_CHARS), AfterValidator(_plain_query)
]


VersionId = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]
QueryVersionId = Annotated[int, Field(ge=1, le=2**63 - 1)]


class VersionQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: QueryVersionId | None = None


class TreeQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    commit: FullHex
    path: str = Field(default="", max_length=_MAX_PATH_TEXT, repr=False)
    version: QueryVersionId | None = None

    @field_validator("path")
    @classmethod
    def _path_segments(cls, path: str) -> str:
        _checked_path(path.split(".") if path else [])
        return path

    def segments(self) -> PathSegments:
        return decoded(self.path.split(".")) if self.path else ()


class NamesIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    commit: FullHex
    query: Query = Field(repr=False)
    version: VersionId | None = None


class FileIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    commit: FullHex
    path: PathIn = Field(min_length=1, repr=False)
    version: VersionId | None = None

    def segments(self) -> PathSegments:
        return decoded(self.path)


class SearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    commit: FullHex
    query: Query = Field(repr=False)
    folder: PathIn = Field(default_factory=list, repr=False)
    version: VersionId | None = None

    def folder_segments(self) -> PathSegments:
        return decoded(self.folder)


class HistoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    skip: int = Field(default=0, strict=True, ge=0, le=MAX_HISTORY_SKIP)
    query: Query | None = Field(default=None, repr=False)
    version: VersionId | None = None


class UnavailableOut(BaseModel):
    unavailable: Unavailable


class SegmentOut(BaseModel):
    raw: str = Field(repr=False)
    name: str = Field(repr=False)


class EntryOut(SegmentOut):
    kind: EntryKind
    size: int | None
    object_id: str


class FolderListOut(BaseModel):
    entries: list[EntryOut]
    total: int
    truncated: bool


class FolderOut(RootModel[FolderListOut | UnavailableOut]):
    pass


class MarkOut(BaseModel):
    line: int
    start: int
    end: int
    subject: str | None


class FirstFoundOut(BaseModel):
    commit: str
    line: int


class MarkedSubjectOut(BaseModel):
    key: str
    kind: SubjectKind
    id: int
    type: str
    status: SecretStatus
    value: str = Field(repr=False)
    value_cut: bool
    possible_canary: bool
    line: int | None
    in_text: bool
    first_found: FirstFoundOut | None


class FileShownOut(BaseModel):
    text: str | None = Field(repr=False)
    binary: bool
    too_large: bool
    size: int
    integrity_failed: bool
    marks: list[MarkOut]
    marks_truncated: bool
    marks_dropped: bool
    subjects: list[MarkedSubjectOut]
    subjects_cut: bool
    lines_unchecked: bool
    last_change_id: int
    canary_unchecked: bool


class FileOut(RootModel[FileShownOut | UnavailableOut]):
    pass


class IdentOut(BaseModel):
    name: str = Field(repr=False)
    email: str = Field(repr=False)
    at: datetime | None


class CommitReadOut(BaseModel):
    id: str
    tree: str
    parents: list[str]
    children: list[str] | None
    children_unavailable: Unavailable | None
    author: IdentOut
    committer: IdentOut
    message: list[MessageLineOut]
    message_cut: bool
    integrity_failed: bool
    marks_dropped: bool


class CommitOut(RootModel[CommitReadOut | UnavailableOut]):
    pass


class HistoryRowOut(BaseModel):
    id: str
    parents: list[str]
    author: IdentOut
    subject: MessageLineOut
    subject_cut: bool
    too_large: bool
    holds_findings: bool


class HistoryPageOut(BaseModel):
    rows: list[HistoryRowOut]
    next_skip: int | None
    scanned: int
    cut: bool
    unread: int
    marks_dropped: bool


class ExplorerHistoryOut(RootModel[HistoryPageOut | UnavailableOut]):
    pass


class RefOut(BaseModel):
    name: str = Field(repr=False)
    kind: RefKind
    target: str | None


class RefListOut(BaseModel):
    refs: list[RefOut]
    truncated: bool


class RefsOut(RootModel[RefListOut | UnavailableOut]):
    pass


class HeadCommitOut(BaseModel):
    commit: str


class HeadOut(RootModel[HeadCommitOut | UnavailableOut]):
    pass


class NameHitOut(BaseModel):
    path: list[SegmentOut]
    kind: EntryKind


class NameHitListOut(BaseModel):
    hits: list[NameHitOut]
    cut: bool


class NameHitsOut(RootModel[NameHitListOut | UnavailableOut]):
    pass


class LineHitOut(BaseModel):
    path: list[SegmentOut]
    line: int
    text: str = Field(repr=False)
    start: int
    end: int
    cut: bool


class SearchHitsOut(BaseModel):
    hits: list[LineHitOut]
    files: int
    skipped_large: int
    skipped_binary: int
    cut: bool


class SearchOut(RootModel[SearchHitsOut | UnavailableOut]):
    pass


class PlaceOut(BaseModel):
    repository_id: int
    commit: str
    path: list[SegmentOut]
    line: int


def shown(text: str) -> str:
    return clean_line(text)


def shown_name(name: bytes) -> str:
    return shown(name.decode("utf-8", "replace"))


def segment_out(name: bytes) -> SegmentOut:
    return SegmentOut(raw=spelled(name), name=shown_name(name))


def utf16_offsets(text: str, offsets: Iterable[int]) -> dict[int, int]:
    found: dict[int, int] = {}
    at = units = 0
    for offset in sorted(set(offsets)):
        units += len(text[at:offset].encode("utf-16-le", "surrogatepass")) // 2
        found[offset] = units
        at = offset
    return found
