import base64
import binascii
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from gitmortem.db.models import UploadFailure, UploadRepoOutcome, UploadRepoRefusal, UploadState
from gitmortem.scanning.imports import CLIENT_NAME_CHARS, NAME_CHARS
from gitmortem.scanning.settings import UPLOAD_BYTES_CEILING
from gitmortem.uploads.pieces import PIECE_BYTES
from gitmortem.uploads.records import UploadRefusal

MAX_UPLOAD_PIECES = UPLOAD_BYTES_CEILING // PIECE_BYTES
PIECE_CHARS = 4 * -(-PIECE_BYTES // 3)
MAX_PIECE_BODY_BYTES = 350_000
MAX_ID = 2**63 - 1


class RepoUploadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_name: str = Field(min_length=1, max_length=CLIENT_NAME_CHARS)
    size_bytes: int = Field(strict=True, ge=1, le=UPLOAD_BYTES_CEILING)
    last_modified_ms: int = Field(strict=True, ge=0, le=2**53)
    org: str | None = Field(default=None, min_length=1, max_length=NAME_CHARS)


class RepoUploadPieceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    seq: int = Field(strict=True, ge=1, le=MAX_UPLOAD_PIECES)
    data: str = Field(max_length=PIECE_CHARS, repr=False)

    def piece(self) -> bytes:
        try:
            return base64.b64decode(self.data, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("a piece is base64") from None


class AnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_id: int | None = Field(default=None, strict=True, ge=1, le=MAX_ID)


class UploadListQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=100_000)
    per_page: int = Field(default=50, ge=1, le=200)


class UploadOut(BaseModel):
    id: int
    client_name: str
    org: str | None
    size_bytes: int
    last_modified_ms: int
    pieces: int
    piece_bytes: int
    pieces_received: int
    state: UploadState
    failure: UploadFailure | None
    created_by: str | None
    mine: bool
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None
    expires_at: datetime | None
    scan_id: int | None


class CandidateOut(BaseModel):
    repository_id: int
    display_path: str
    org: str | None
    name: str
    commit_count: int | None
    current_version_at: datetime | None
    current_version_by: str | None


class UploadRepoOut(BaseModel):
    id: int
    zip_path: str
    org: str | None
    name: str
    outcome: UploadRepoOutcome
    refusal: UploadRepoRefusal | None
    repository_id: int | None
    candidates: list[CandidateOut]
    dropped_objects: int


class UploadDetailOut(UploadOut):
    repos: list[UploadRepoOut]


class UploadPageOut(BaseModel):
    items: list[UploadOut]
    page: int
    per_page: int
    total: int


class UploadRefusedOut(BaseModel):
    message: str
    detail: dict[str, UploadRefusal]
