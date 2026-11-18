import base64
import binascii
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from gitmortem.db.models import ImportFailure, ImportSource, ImportState, ToolName
from gitmortem.scanning import imports
from gitmortem.scanning.imports import (
    CLIENT_NAME_CHARS,
    MAX_IMPORT_BYTES,
    MAX_PIECE_BYTES,
    NAME_CHARS,
    SERVER_PATH_CHARS,
    ImportRefusal,
    ImportTarget,
    NotOnDisk,
    RepositoryId,
)
from gitmortem.web.schemas import MAX_ID, RowId, add_model_schemas

ImportableTool = Literal[ToolName.GIT_SECRETS, ToolName.GITLEAKS, ToolName.TRUFFLEHOG]
PIECE_CHARS = 4 * -(-MAX_PIECE_BYTES // 3)
MAX_PIECES = MAX_IMPORT_BYTES // MAX_PIECE_BYTES


def _plain(limit: int) -> AfterValidator:
    return AfterValidator(lambda text: imports.plain_name(text, limit))


Name = Annotated[str, Field(min_length=1, max_length=NAME_CHARS), _plain(NAME_CHARS)]
ClientName = Annotated[
    str, Field(min_length=1, max_length=CLIENT_NAME_CHARS), _plain(CLIENT_NAME_CHARS)
]


class RepositoryTargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_id: RowId

    def target(self) -> ImportTarget:
        return RepositoryId(self.repository_id)


class NotOnDiskTargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    org: Name
    name: Name

    def target(self) -> ImportTarget:
        return NotOnDisk(self.org, self.name)


class UploadIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tool: ImportableTool
    target: RepositoryTargetIn | NotOnDiskTargetIn
    client_name: ClientName | None = None
    size_bytes: int = Field(strict=True, ge=0, le=MAX_ID)


class PieceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    seq: int = Field(strict=True, ge=1, le=MAX_PIECES)
    data: str = Field(max_length=PIECE_CHARS, repr=False)

    def piece(self) -> bytes:
        try:
            return base64.b64decode(self.data, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("a piece is base64") from None


class ServerFileIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tool: ImportableTool
    target: RepositoryTargetIn | NotOnDiskTargetIn
    path: str = Field(min_length=1, max_length=SERVER_PATH_CHARS)


class ImportQueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, le=1_000_000_000)
    per_page: int = Field(default=50, ge=1, le=200)


class ImportCheckOut(BaseModel):
    records: int
    values: int
    standalone: int
    redacted: int
    unknown_commits: int
    parse_issues: int
    reported_live: int


class ImportOut(BaseModel):
    id: int
    scan_id: int
    tool: ToolName
    repository_id: int
    repository: str
    repository_on_disk: bool
    state: ImportState
    source: ImportSource
    client_name: str | None
    server_path: str | None
    size_bytes: int
    pieces: int
    pieces_received: int
    check: ImportCheckOut | None
    failure: ImportFailure | None
    failure_reason: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    recorded_at: datetime | None
    removed_at: datetime | None
    removed_by: str | None
    removable: bool
    mine: bool


class ImportPageOut(BaseModel):
    items: list[ImportOut]
    page: int
    per_page: int
    total: int


class RemovalOut(BaseModel):
    findings: int
    secrets: int
    with_triage: int
    digest: str


class RemovalIn(BaseModel):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ImportRefusedDetail(BaseModel):
    reason: ImportRefusal | None = None
    json_: dict[str, list[str]] | None = Field(default=None, alias="json")


class ImportRefusedOut(BaseModel):
    message: str
    detail: ImportRefusedDetail


REFUSAL_MODELS: tuple[type[BaseModel], ...] = (ImportRefusedOut,)


def add_refusal_schemas(spec: dict[Any, Any] | str) -> dict[Any, Any] | str:
    added: dict[Any, Any] | str = add_model_schemas(spec, REFUSAL_MODELS)
    return added
