from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import (
    AuditValue,
    InstanceSetting,
    ToolName,
    ToolSetting,
    User,
    utcnow,
)
from gitmortem.scanning.options import ToolOptions, option_changes, options_json, options_model

DEFAULT_TIMEOUT_SECONDS = 1800
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 86400
DEFAULT_SCAN_WORKERS = 2
MIN_SCAN_WORKERS = 1
MAX_SCAN_WORKERS = 8
INSTANCE_SETTINGS_ID = 1

UPLOAD_BYTES_CEILING = 64 << 30
DEFAULT_UPLOAD_BYTES = 16 << 30
ZIP_ENTRIES_CEILING = 5_000_000
DEFAULT_ZIP_ENTRIES = 2_000_000
UNPACKED_BYTES_CEILING = 256 << 30
DEFAULT_UNPACKED_BYTES = 64 << 30
RATIO_CEILING = 100
DEFAULT_RATIO = 100
IMPORT_BYTES_CEILING = 256 << 20
DEFAULT_IMPORT_BYTES = 256 << 20


@dataclass(frozen=True)
class ToolSettings:
    enabled: bool = True
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


def get_tool_settings(db: Session, tool: ToolName) -> ToolSettings:
    row = db.get(ToolSetting, tool)
    if row is None:
        return ToolSettings()
    return ToolSettings(enabled=row.enabled, timeout_seconds=row.timeout_seconds)


def set_tool_settings(
    db: Session,
    tool: ToolName,
    *,
    enabled: bool | None,
    timeout_seconds: int | None,
    actor: User,
) -> tuple[ToolSettings, ToolSettings]:
    before = get_tool_settings(db, tool)
    after = ToolSettings(
        enabled=before.enabled if enabled is None else enabled,
        timeout_seconds=before.timeout_seconds if timeout_seconds is None else timeout_seconds,
    )
    if not MIN_TIMEOUT_SECONDS <= after.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError("timeout_seconds is out of range")
    row = db.get(ToolSetting, tool)
    if row is None:
        row = ToolSetting(tool=tool)
        db.add(row)
    row.enabled = after.enabled
    row.timeout_seconds = after.timeout_seconds
    row.updated_by_user_id = actor.id
    row.updated_at = utcnow()
    db.flush()
    return before, after


_MOST_REPAIRS = 8


def get_tool_options(db: Session, tool: ToolName) -> ToolOptions:
    row = db.get(ToolSetting, tool)
    options, _ = _lenient(options_model(tool), {} if row is None else dict(row.options))
    return options


def _lenient(model: type[ToolOptions], stored: dict[str, Any]) -> tuple[ToolOptions, list[str]]:
    held = dict(stored)
    dropped: list[str] = []
    for _ in range(_MOST_REPAIRS):
        try:
            return model.model_validate(held), dropped
        except ValidationError as refused:
            names = {str(error["loc"][0]) for error in refused.errors() if error["loc"]} & set(held)
            if not names:
                break
            for name in sorted(names):
                dropped.append(name)
                value = held.pop(name)
                if isinstance(value, list):
                    kept = [item for item in value if _valid(model, {name: [item]})]
                    if kept:
                        held[name] = kept
    return model(), [*dropped, *held]


def _valid(model: type[ToolOptions], values: dict[str, Any]) -> bool:
    try:
        model.model_validate(values)
    except ValidationError:
        return False
    return True


def repair_tool_options(db: Session) -> None:
    for row in db.scalars(select(ToolSetting)):
        model = options_model(row.tool)
        try:
            model.model_validate(row.options)
        except ValidationError:
            options, dropped = _lenient(model, dict(row.options))
            row.options = options_json(options)
            repaired: list[AuditValue] = [*sorted(set(dropped))]
            audit.record(
                db,
                AuditAction.TOOL_SETTINGS_CHANGED,
                actor=None,
                detail={"tool": row.tool.value, "repaired": repaired},
            )
    db.flush()


def set_tool_options(
    db: Session, tool: ToolName, options: ToolOptions, actor: User, *, ip: str | None = None
) -> tuple[ToolOptions | None, ToolOptions]:
    model = options_model(tool)
    if type(options) is not model:
        raise TypeError(f"these are not {tool.value}'s options")
    row = db.get(ToolSetting, tool)
    stored: dict[str, Any] = {} if row is None else dict(row.options)
    try:
        before: ToolOptions | None = model.model_validate(stored)
    except ValidationError:
        before = None
    if row is None:
        row = ToolSetting(tool=tool)
        db.add(row)
    row.options = options_json(options)
    row.updated_by_user_id = actor.id
    row.updated_at = utcnow()
    db.flush()
    if before is not None:
        changes = option_changes(before, options)
    else:
        old = {**options_json(model()), **stored}
        new = options_json(options)
        changes = {name: [old[name], new[name]] for name in new if old[name] != new[name]}
    if changes:
        audit.record(
            db,
            AuditAction.TOOL_SETTINGS_CHANGED,
            actor=actor,
            ip=ip,
            detail={"tool": tool.value, "options": changes},
        )
    return before, options


def get_scan_workers(db: Session) -> int:
    row = db.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    return DEFAULT_SCAN_WORKERS if row is None else row.scan_workers


def set_scan_workers(db: Session, workers: int) -> tuple[int, int]:
    if not MIN_SCAN_WORKERS <= workers <= MAX_SCAN_WORKERS:
        raise ValueError("scan_workers is out of range")
    before = get_scan_workers(db)
    row = db.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    if row is None:
        row = InstanceSetting(id=INSTANCE_SETTINGS_ID)
        db.add(row)
    row.scan_workers = workers
    db.flush()
    return before, workers


@dataclass(frozen=True)
class UploadLimits:
    upload_bytes: int
    zip_entries: int
    unpacked_bytes: int
    ratio: int
    import_bytes: int


UPLOAD_LIMIT_CEILINGS = UploadLimits(
    upload_bytes=UPLOAD_BYTES_CEILING,
    zip_entries=ZIP_ENTRIES_CEILING,
    unpacked_bytes=UNPACKED_BYTES_CEILING,
    ratio=RATIO_CEILING,
    import_bytes=IMPORT_BYTES_CEILING,
)
UPLOAD_LIMIT_DEFAULTS = UploadLimits(
    upload_bytes=DEFAULT_UPLOAD_BYTES,
    zip_entries=DEFAULT_ZIP_ENTRIES,
    unpacked_bytes=DEFAULT_UNPACKED_BYTES,
    ratio=DEFAULT_RATIO,
    import_bytes=DEFAULT_IMPORT_BYTES,
)
UPLOAD_LIMIT_FIELDS = tuple(UploadLimits.__dataclass_fields__)


def get_upload_limits(db: Session) -> UploadLimits:
    row = db.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    values: dict[str, int] = {}
    for field in UPLOAD_LIMIT_FIELDS:
        stored = None if row is None else getattr(row, field)
        value = getattr(UPLOAD_LIMIT_DEFAULTS, field) if stored is None else stored
        values[field] = min(value, getattr(UPLOAD_LIMIT_CEILINGS, field))
    return UploadLimits(**values)


def set_upload_limits(db: Session, **changes: int) -> dict[str, tuple[int, int]]:
    for field, value in changes.items():
        if field not in UPLOAD_LIMIT_FIELDS:
            raise ValueError(f"{field} is not an upload limit")
        if not 1 <= value <= getattr(UPLOAD_LIMIT_CEILINGS, field):
            raise ValueError(f"{field} is out of range")
    before = get_upload_limits(db)
    changed = {
        field: (getattr(before, field), value)
        for field, value in changes.items()
        if getattr(before, field) != value
    }
    if not changed:
        return {}
    row = db.get(InstanceSetting, INSTANCE_SETTINGS_ID)
    if row is None:
        row = InstanceSetting(id=INSTANCE_SETTINGS_ID, scan_workers=DEFAULT_SCAN_WORKERS)
        db.add(row)
    for field, (_, value) in changed.items():
        setattr(row, field, value)
    db.flush()
    return changed
