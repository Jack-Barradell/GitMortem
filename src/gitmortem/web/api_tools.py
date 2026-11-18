from collections.abc import Mapping

from apiflask import APIBlueprint, abort
from flask import current_app
from flask_login import current_user
from pydantic import ValidationError
from sqlalchemy.orm import Session

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import Role, ToolName
from gitmortem.gitrun import GitError, GitUnavailable
from gitmortem.scanning import settings as scan_settings
from gitmortem.scanning.options import (
    ToolOptions,
    option_descriptors,
    options_json,
    options_model,
)
from gitmortem.scanning.registry import TESTED_VERSIONS, TOOLS
from gitmortem.scanning.rules import enabled_rule_ids
from gitmortem.scanning.tools import Detection, detection_changes
from gitmortem.triage import canary
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import end_read_transaction, get_db
from gitmortem.web.scans import running_scans
from gitmortem.web.schemas import (
    CanaryWordsIn,
    CanaryWordsOut,
    OptionDescriptorListOut,
    OptionDescriptorOut,
    ScanSettingsIn,
    ScanSettingsOut,
    ToolListOut,
    ToolOut,
    ToolSettingsIn,
    ToolSettingsOut,
    UploadLimitsIn,
    UploadLimitsOut,
    UploadLimitValuesOut,
)
from gitmortem.web.sealing import app_sealer
from gitmortem.web.security import client_ip, require_recent_password, require_role

bp = APIBlueprint("tools", __name__, url_prefix="/api")
NO_SUCH_TOOL = "No such tool."
NO_GIT = "git is not available"
NO_DETECTION = "The tools could not be detected: GitMortem could not use its data directory"


def _tool(name: str) -> ToolName:
    try:
        return ToolName(name)
    except ValueError:
        get_db().rollback()
        abort(404, NO_SUCH_TOOL)


def _options(tool: ToolName, sent: Mapping[str, object]) -> ToolOptions:
    try:
        return options_model(tool).model_validate(sent)
    except ValidationError as error:
        fields: dict[str, list[str]] = {}
        for found in error.errors(include_url=False, include_input=False):
            where = ".".join(str(part) for part in ("options", *found["loc"]))
            fields.setdefault(where, []).append(found["msg"])
        abort(422, current_app.config["VALIDATION_ERROR_DESCRIPTION"], detail={"json": fields})


def _tools_out(found: Mapping[ToolName, Detection]) -> ToolListOut:
    db = get_db()
    is_admin = current_user.role is Role.ADMIN
    rows = []
    for name in TOOLS:
        detection = found.get(name)
        saved = scan_settings.get_tool_settings(db, name)
        rows.append(
            ToolOut(
                name=name,
                status=None if detection is None else detection.status,
                identity=None if detection is None else detection.identity,
                sha256=None if detection is None else detection.sha256,
                git_version=None if detection is None else detection.git_version,
                usable=detection is not None and detection.usable,
                enabled=saved.enabled,
                timeout_seconds=saved.timeout_seconds,
                path=(
                    str(detection.path)
                    if is_admin and detection is not None and detection.path is not None
                    else None
                ),
                options=options_json(scan_settings.get_tool_options(db, name)),
                tested_version=TESTED_VERSIONS.get(name),
                enabled_rules=len(enabled_rule_ids(db)) if name is ToolName.CUSTOM_RULES else None,
            )
        )
    return ToolListOut(rows)


@bp.get("/tools", endpoint="list")
@require_role(Role.ANALYST)
@bp.output(ToolListOut)
@bp.doc(responses={503: "Scanning is not running"})
def list_tools() -> ToolListOut:
    return _tools_out(running_scans().detections)


@bp.post("/tools/detect", endpoint="detect")
@require_role(Role.ADMIN)
@bp.output(ToolListOut)
@bp.doc(
    responses={
        503: "Scanning is not running, git is not available, or the data directory could not "
        "be used"
    }
)
def detect() -> ToolListOut:
    service = running_scans()
    before = dict(service.detections)
    end_read_transaction()
    try:
        found = service.detect()
    except (GitUnavailable, GitError):
        abort(503, NO_GIT)
    except OSError:
        abort(503, NO_DETECTION)
    audit.record(
        get_db(),
        AuditAction.TOOLS_DETECTED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"changed": detection_changes(before, found)},
    )
    return _tools_out(found)


@bp.patch("/tools/<name>", endpoint="update")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(ToolSettingsIn, arg_name="change")
@bp.output(ToolSettingsOut)
@bp.doc(responses={404: NO_SUCH_TOOL})
def update_tool(name: str, change: ToolSettingsIn) -> ToolSettingsOut:
    tool = _tool(name)
    db = get_db()
    options = None if change.options is None else _options(tool, change.options)
    actor = current_actor()
    before, after = scan_settings.set_tool_settings(
        db, tool, enabled=change.enabled, timeout_seconds=change.timeout_seconds, actor=actor
    )
    detail: dict[str, str | int | bool] = {"tool": tool.value}
    if before.enabled != after.enabled:
        detail["enabled"] = f"{str(before.enabled).lower()} -> {str(after.enabled).lower()}"
    if before.timeout_seconds != after.timeout_seconds:
        detail["timeout_seconds"] = f"{before.timeout_seconds} -> {after.timeout_seconds}"
    if len(detail) > 1:
        audit.record(
            db, AuditAction.TOOL_SETTINGS_CHANGED, actor=actor, ip=client_ip(), detail=detail
        )
    if options is not None:
        scan_settings.set_tool_options(db, tool, options, actor, ip=client_ip())
    return ToolSettingsOut(
        name=tool,
        enabled=after.enabled,
        timeout_seconds=after.timeout_seconds,
        options=options_json(scan_settings.get_tool_options(db, tool)),
    )


@bp.get("/tools/<name>/options", endpoint="options")
@require_role(Role.ADMIN)
@bp.output(OptionDescriptorListOut)
@bp.doc(responses={404: NO_SUCH_TOOL})
def tool_options(name: str) -> OptionDescriptorListOut:
    tool = _tool(name)
    return OptionDescriptorListOut(
        [OptionDescriptorOut(**found) for found in option_descriptors(options_model(tool))]
    )


@bp.get("/settings/scanning", endpoint="scan_settings")
@require_role(Role.ADMIN)
@bp.output(ScanSettingsOut)
def get_scan_settings() -> ScanSettingsOut:
    return ScanSettingsOut(scan_workers=scan_settings.get_scan_workers(get_db()))


@bp.patch("/settings/scanning", endpoint="update_scan_settings")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(ScanSettingsIn, arg_name="change")
@bp.output(ScanSettingsOut)
def update_scan_settings(change: ScanSettingsIn) -> ScanSettingsOut:
    db = get_db()
    before, after = scan_settings.set_scan_workers(db, change.scan_workers)
    if before != after:
        audit.record(
            db,
            AuditAction.SCAN_SETTINGS_CHANGED,
            actor=current_actor(),
            ip=client_ip(),
            detail={"scan_workers": f"{before} -> {after}"},
        )
    return ScanSettingsOut(scan_workers=after)


def _words_out(db: Session) -> CanaryWordsOut:
    return CanaryWordsOut(
        built_in=list(canary.BUILT_IN_WORDS),
        words=list(canary.own_words(db, app_sealer())),
        most=canary.MAX_OWN_WORDS,
        shortest=canary.MIN_WORD_CHARS,
        longest=canary.MAX_WORD_CHARS,
    )


@bp.get("/settings/canary-words", endpoint="canary_words")
@require_role(Role.ADMIN)
@bp.output(CanaryWordsOut)
def get_canary_words() -> CanaryWordsOut:
    return _words_out(get_db())


@bp.patch("/settings/canary-words", endpoint="update_canary_words")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(CanaryWordsIn, arg_name="change")
@bp.output(CanaryWordsOut)
@bp.doc(responses={422: "More words than allowed, or a word too short or too long"})
def update_canary_words(change: CanaryWordsIn) -> CanaryWordsOut:
    db = get_db()
    try:
        changed = canary.set_own_words(db, app_sealer(), change.words)
    except ValueError as refused:
        db.rollback()
        abort(422, message=str(refused))
    if changed is not None:
        before, after = changed
        audit.record(
            db,
            AuditAction.CANARY_WORDS_CHANGED,
            actor=current_actor(),
            ip=client_ip(),
            detail={"words": f"{before} -> {after}"},
        )
    return _words_out(db)


def _limits_out(limits: scan_settings.UploadLimits) -> UploadLimitsOut:
    ceilings = scan_settings.UPLOAD_LIMIT_CEILINGS
    return UploadLimitsOut(
        **{field: getattr(limits, field) for field in scan_settings.UPLOAD_LIMIT_FIELDS},
        ceilings=UploadLimitValuesOut(
            **{field: getattr(ceilings, field) for field in scan_settings.UPLOAD_LIMIT_FIELDS}
        ),
    )


@bp.get("/settings/uploads", endpoint="upload_limits")
@require_role(Role.ADMIN)
@bp.output(UploadLimitsOut)
def get_upload_limits() -> UploadLimitsOut:
    return _limits_out(scan_settings.get_upload_limits(get_db()))


@bp.patch("/settings/uploads", endpoint="update_upload_limits")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(UploadLimitsIn, arg_name="change")
@bp.output(UploadLimitsOut)
def update_upload_limits(change: UploadLimitsIn) -> UploadLimitsOut:
    db = get_db()
    named = {field: getattr(change, field) for field in change.model_fields_set}
    changed = scan_settings.set_upload_limits(db, **named)
    if changed:
        audit.record(
            db,
            AuditAction.UPLOAD_LIMITS_CHANGED,
            actor=current_actor(),
            ip=client_ip(),
            detail={field: f"{old} -> {new}" for field, (old, new) in changed.items()},
        )
    return _limits_out(scan_settings.get_upload_limits(db))
