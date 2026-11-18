from dataclasses import asdict
from typing import Any, NoReturn

from apiflask import APIBlueprint, abort

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import AuditValue, Role
from gitmortem.scanning import rules
from gitmortem.scanning.rule_patterns import MAX_PATTERN_CHARS, MAX_PROGRAM_SIZE, RuleRefusal
from gitmortem.scanning.rules import MAX_RULES, RuleRefused, RulesRefused, RuleView
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import end_read_transaction, get_db
from gitmortem.web.rules_schemas import (
    RuleChangeIn,
    RuleEntryOut,
    RuleIn,
    RuleListOut,
    RuleMatchOut,
    RuleOut,
    RulesFileIn,
    RulesFileOut,
    RuleTestIn,
    RuleTestOut,
)
from gitmortem.web.schemas import described
from gitmortem.web.sealing import app_sealer
from gitmortem.web.security import client_ip, now, require_role

bp = APIBlueprint("rules", __name__, url_prefix="/api/rules")
RULE_ID = "<id:rule_id>"
NO_SUCH_RULE = "No such rule."
UNKNOWN_EXCHANGE = (
    "This is not a GitMortem rules file this version reads: it must say format "
    f'"{rules.EXCHANGE_FORMAT}" and version {rules.EXCHANGE_VERSION}.'
)
FILE_REFUSED = "The rules file was refused; nothing was imported."
REFUSALS: dict[RuleRefusal, str] = {
    RuleRefusal.TOO_LONG: f"The pattern is longer than {MAX_PATTERN_CHARS:,} characters.",
    RuleRefusal.DOES_NOT_COMPILE: "The pattern is not a regular expression RE2 accepts.",
    RuleRefusal.TOO_COMPLEX: (
        f"The pattern is too complex: it compiles to more than {MAX_PROGRAM_SIZE:,} RE2 "
        "instructions."
    ),
    RuleRefusal.BAD_VALUE_GROUP: "A pattern's only named group may be one called value.",
    RuleRefusal.NAME_TAKEN: "Another rule has this name.",
    RuleRefusal.TOO_MANY: f"GitMortem keeps at most {MAX_RULES:,} rules.",
    RuleRefusal.INVALID: (
        "Not a rule: each needs a name and a pattern, may have a description and enabled, "
        "and nothing else."
    ),
}
REFUSED_422: dict[str, Any] = {
    "description": (
        "A field out of its bounds (`detail.json`), or a pattern or name refused "
        "(`detail.reason`); nothing was written"
    ),
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RuleRefusedOut"}}},
}
FILE_REFUSED_422: dict[str, Any] = {
    "description": (
        "Another format or version, or a refused file: `detail.refused` names every reason, "
        "each with its entry's index (null for too_many, which is the file's); nothing was "
        "written"
    ),
    "content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/RulesFileRefusedOut"}}
    },
}


def _refused(reason: RuleRefusal) -> NoReturn:
    get_db().rollback()
    abort(422, REFUSALS[reason], detail={"reason": reason.value})


def _out(view: RuleView) -> RuleOut:
    return RuleOut(**asdict(view))


@bp.get("", endpoint="list")
@require_role(Role.ADMIN)
@bp.output(RuleListOut)
def list_rules() -> RuleListOut:
    return RuleListOut([_out(view) for view in rules.list_rules(get_db(), app_sealer())])


@bp.post("", endpoint="create")
@require_role(Role.ADMIN)
@bp.input(RuleIn, arg_name="new")
@bp.output(RuleOut, status_code=201)
@bp.doc(responses=described({422: REFUSED_422}))
def create(new: RuleIn) -> tuple[RuleOut, int]:
    db, sealer, actor = get_db(), app_sealer(), current_actor()
    try:
        rule = rules.create_rule(db, sealer, new, user=actor, now=now())
    except RuleRefused as refused:
        _refused(refused.reason)
    audit.record(
        db,
        AuditAction.RULE_CREATED,
        actor=actor,
        ip=client_ip(),
        detail={"rule_id": rule.id, "name": rule.name, "enabled": rule.enabled},
    )
    return _out(rules.view_rule(db, sealer, rule)), 201


@bp.patch(f"/{RULE_ID}", endpoint="update")
@require_role(Role.ADMIN)
@bp.input(RuleChangeIn, arg_name="change")
@bp.output(RuleOut)
@bp.doc(responses=described({404: NO_SUCH_RULE, 422: REFUSED_422}))
def update(rule_id: int, change: RuleChangeIn) -> RuleOut:
    db, sealer, actor = get_db(), app_sealer(), current_actor()
    try:
        done = rules.change_rule(
            db,
            sealer,
            rule_id,
            user=actor,
            now=now(),
            name=change.name,
            description=change.description,
            pattern=change.pattern,
            enabled=change.enabled,
        )
    except rules.NoSuchRule:
        db.rollback()
        abort(404, NO_SUCH_RULE)
    except RuleRefused as refused:
        _refused(refused.reason)
    if done.changed:
        rule = done.rule
        detail: dict[str, AuditValue] = {
            "rule_id": rule.id,
            "name": rule.name,
            "changed": [*done.changed],
        }
        if "name" in done.changed:
            detail["previous_name"] = done.previous_name
        if "enabled" in done.changed:
            detail["enabled"] = (
                f"{str(done.previous_enabled).lower()} -> {str(rule.enabled).lower()}"
            )
        audit.record(db, AuditAction.RULE_CHANGED, actor=actor, ip=client_ip(), detail=detail)
    return _out(rules.view_rule(db, sealer, done.rule))


@bp.delete(f"/{RULE_ID}", endpoint="delete")
@require_role(Role.ADMIN)
@bp.doc(
    responses={
        204: "Deleted; its findings keep custom:<id>, which no later rule is given",
        404: NO_SUCH_RULE,
    }
)
def delete(rule_id: int) -> tuple[str, int]:
    db = get_db()
    try:
        deleted = rules.delete_rule(db, rule_id)
    except rules.NoSuchRule:
        db.rollback()
        abort(404, NO_SUCH_RULE)
    audit.record(
        db,
        AuditAction.RULE_DELETED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"rule_id": deleted.id, "name": deleted.name},
    )
    return "", 204


@bp.post("/test", endpoint="test")
@require_role(Role.ADMIN)
@bp.input(RuleTestIn, arg_name="trial")
@bp.output(RuleTestOut)
@bp.doc(responses=described({422: REFUSED_422}))
def try_pattern(trial: RuleTestIn) -> RuleTestOut:
    end_read_transaction()
    found = rules.try_rule(trial.pattern, trial.sample)
    if isinstance(found, RuleRefusal):
        abort(422, REFUSALS[found], detail={"reason": found.value})
    return RuleTestOut(matches=[RuleMatchOut(**asdict(match)) for match in found])


@bp.post("/export", endpoint="export")
@require_role(Role.ADMIN)
@bp.output(RulesFileOut)
def export() -> RulesFileOut:
    db = get_db()
    entries = rules.export_rules(db, app_sealer())
    audit.record(
        db,
        AuditAction.RULES_EXPORTED,
        actor=current_actor(),
        ip=client_ip(),
        detail={"count": len(entries)},
    )
    return RulesFileOut(
        format=rules.EXCHANGE_FORMAT,
        version=rules.EXCHANGE_VERSION,
        rules=[RuleEntryOut(**entry.model_dump()) for entry in entries],
    )


@bp.post("/import", endpoint="import")
@require_role(Role.ADMIN)
@bp.input(RulesFileIn, arg_name="document")
@bp.output(RuleListOut, status_code=201)
@bp.doc(
    responses=described(
        {
            413: "A file over 1 MiB, refused before it is read: import it in parts",
            422: FILE_REFUSED_422,
        }
    )
)
def import_file(document: RulesFileIn) -> tuple[RuleListOut, int]:
    try:
        rules.check_exchange(document.format, document.version)
    except rules.UnknownExchange:
        abort(422, UNKNOWN_EXCHANGE)
    end_read_transaction()
    try:
        checked = rules.check_entries(document.rules)
        db, sealer, actor = get_db(), app_sealer(), current_actor()
        made = rules.import_rules(db, sealer, checked, user=actor, now=now())
    except RulesRefused as refused:
        get_db().rollback()
        reasons = [
            {"index": found.index, "reason": found.reason.value} for found in refused.refused
        ]
        abort(422, FILE_REFUSED, detail={"refused": reasons})
    audit.record(
        db,
        AuditAction.RULES_IMPORTED,
        actor=actor,
        ip=client_ip(),
        detail={
            "count": len(made),
            "rules": [
                {"id": rule.id, "name": rule.name} for rule in made[: audit.NAME_SUBJECTS_UP_TO]
            ],
        },
    )
    views = rules.list_rules(db, sealer, ids=[rule.id for rule in made])
    return RuleListOut([_out(view) for view in views]), 201
