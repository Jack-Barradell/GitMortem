import re
from bisect import bisect_left
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import CustomRule, User
from gitmortem.scanning.rule_patterns import VALUE_GROUP, RuleRefusal, StoredRule, compile_rule

MAX_RULES = 1_000
MAX_NAME_CHARS = 100
MAX_DESCRIPTION_CHARS = 1_000
MAX_SAMPLE_CHARS = 65_536
ExchangeFormat = Literal["gitmortem-rules"]
ExchangeVersion = Literal[1]
EXCHANGE_FORMAT: Final[ExchangeFormat] = "gitmortem-rules"
EXCHANGE_VERSION: Final[ExchangeVersion] = 1

NAME_RULE = f"a name is 1 to {MAX_NAME_CHARS} characters, with no control or bidi characters"
DESCRIPTION_RULE = (
    f"a description is at most {MAX_DESCRIPTION_CHARS:,} characters, with no control "
    "characters but tabs and line breaks"
)
NOT_TEXT = "the text is not valid Unicode"
SAMPLE_RULE = f"a sample is at most {MAX_SAMPLE_CHARS:,} characters"
_NOT_IN_A_NAME = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_NOT_IN_A_DESCRIPTION = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


class RuleRefused(Exception):
    def __init__(self, reason: RuleRefusal) -> None:
        super().__init__(f"rule refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class EntryRefusal:
    index: int | None
    reason: RuleRefusal


class RulesRefused(Exception):
    def __init__(self, refused: Sequence[EntryRefusal]) -> None:
        super().__init__(f"rules file refused for {len(refused)} reasons")
        self.refused = tuple(refused)


class NoSuchRule(LookupError):
    def __init__(self, rule_id: int) -> None:
        super().__init__(f"no rule {rule_id}")
        self.rule_id = rule_id


class UnknownExchange(ValueError):
    def __init__(self) -> None:
        super().__init__(f"not a {EXCHANGE_FORMAT} file of version {EXCHANGE_VERSION}")


@dataclass(frozen=True)
class RuleMatch:
    line: int
    start: int
    end: int
    value_start: int
    value_end: int


@dataclass(frozen=True)
class RuleView:
    id: int
    name: str
    description: str
    pattern: str = field(repr=False)
    enabled: bool
    created_by: str | None
    created_at: datetime
    updated_by: str | None
    updated_at: datetime


@dataclass(frozen=True)
class RuleChange:
    rule: CustomRule
    changed: tuple[str, ...]
    previous_name: str
    previous_enabled: bool


@dataclass(frozen=True)
class DeletedRule:
    id: int
    name: str


FIELDS = ("name", "description", "pattern", "enabled")


def check_text(text: str) -> None:
    try:
        text.encode()
    except UnicodeEncodeError:
        raise ValueError(NOT_TEXT) from None


def clean_name(name: str) -> str:
    check_text(name)
    kept = name.strip()
    if not 1 <= len(kept) <= MAX_NAME_CHARS or _NOT_IN_A_NAME.search(kept):
        raise ValueError(NAME_RULE)
    return kept


def clean_description(text: str) -> str:
    check_text(text)
    kept = text.strip()
    if len(kept) > MAX_DESCRIPTION_CHARS or _NOT_IN_A_DESCRIPTION.search(kept):
        raise ValueError(DESCRIPTION_RULE)
    return kept


class RuleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, frozen=True, strict=True)

    name: str
    description: str = ""
    pattern: str = Field(repr=False)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _clean_name(cls, name: str) -> str:
        return clean_name(name)

    @field_validator("description")
    @classmethod
    def _clean_description(cls, text: str) -> str:
        return clean_description(text)


def _utf16(line: str) -> Callable[[int], int]:
    astral = [] if line.isascii() else [at for at, char in enumerate(line) if ord(char) > 0xFFFF]
    return lambda offset: offset + bisect_left(astral, offset)


def try_rule(pattern: str, sample: str) -> list[RuleMatch] | RuleRefusal:
    if len(sample) > MAX_SAMPLE_CHARS:
        raise ValueError(SAMPLE_RULE)
    check_text(sample)
    compiled = compile_rule(pattern)
    if isinstance(compiled, RuleRefusal):
        return compiled
    group: int = compiled.groupindex.get(VALUE_GROUP, 0)
    found: list[RuleMatch] = []
    for number, line in enumerate(sample.split("\n"), start=1):
        units = _utf16(line)
        for match in compiled.finditer(line):
            value_start, value_end = match.span(group)
            if value_start < 0 or value_start == value_end:
                continue
            start, end = match.span()
            found.append(
                RuleMatch(number, units(start), units(end), units(value_start), units(value_end))
            )
    return found


def _sealed(sealer: Sealer, pattern: str) -> bytes:
    return sealer.seal(pattern.encode(), Purpose.RULE_PATTERN)


def _opened(sealer: Sealer, blob: bytes) -> str:
    return sealer.open(blob, Purpose.RULE_PATTERN).decode()


def _refuse_pattern(pattern: str) -> None:
    compiled = compile_rule(pattern)
    if isinstance(compiled, RuleRefusal):
        raise RuleRefused(compiled)


def _name_taken(session: Session, name: str, *, other_than: int | None = None) -> bool:
    query = select(CustomRule.id).where(CustomRule.name == name)
    if other_than is not None:
        query = query.where(CustomRule.id != other_than)
    return session.scalar(query.limit(1)) is not None


def _count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(CustomRule)) or 0


def _rule(session: Session, rule_id: int) -> CustomRule:
    rule = session.get(CustomRule, rule_id)
    if rule is None:
        raise NoSuchRule(rule_id)
    return rule


def _username(session: Session, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    return session.scalar(select(User.username).where(User.id == user_id))


def _view(
    sealer: Sealer, rule: CustomRule, created_by: str | None, updated_by: str | None
) -> RuleView:
    return RuleView(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        pattern=_opened(sealer, rule.pattern_sealed),
        enabled=rule.enabled,
        created_by=created_by,
        created_at=rule.created_at,
        updated_by=updated_by,
        updated_at=rule.updated_at,
    )


def enabled_rule_ids(session: Session) -> list[int]:
    return list(
        session.scalars(
            select(CustomRule.id).where(CustomRule.enabled.is_(True)).order_by(CustomRule.id)
        )
    )


def stored_rules(session: Session, sealer: Sealer, ids: Collection[int]) -> list[StoredRule]:
    rows = session.execute(
        select(CustomRule.id, CustomRule.name, CustomRule.pattern_sealed)
        .where(CustomRule.id.in_(list(ids)))
        .order_by(CustomRule.id)
    )
    return [StoredRule(rule_id, name, _opened(sealer, blob)) for rule_id, name, blob in rows]


def view_rule(session: Session, sealer: Sealer, rule: CustomRule) -> RuleView:
    return _view(
        sealer,
        rule,
        _username(session, rule.created_by_user_id),
        _username(session, rule.updated_by_user_id),
    )


def list_rules(
    session: Session, sealer: Sealer, *, ids: Collection[int] | None = None
) -> list[RuleView]:
    creator, updater = aliased(User), aliased(User)
    query = (
        select(CustomRule, creator.username, updater.username)
        .outerjoin(creator, creator.id == CustomRule.created_by_user_id)
        .outerjoin(updater, updater.id == CustomRule.updated_by_user_id)
        .order_by(CustomRule.id)
    )
    if ids is not None:
        query = query.where(CustomRule.id.in_(ids))
    return [_view(sealer, rule, made, changed) for rule, made, changed in session.execute(query)]


def create_rule(
    session: Session, sealer: Sealer, rule: RuleEntry, *, user: User, now: datetime
) -> CustomRule:
    _refuse_pattern(rule.pattern)
    if _name_taken(session, rule.name):
        raise RuleRefused(RuleRefusal.NAME_TAKEN)
    if _count(session) >= MAX_RULES:
        raise RuleRefused(RuleRefusal.TOO_MANY)
    made = CustomRule(
        name=rule.name,
        description=rule.description,
        pattern_sealed=_sealed(sealer, rule.pattern),
        enabled=rule.enabled,
        created_by_user_id=user.id,
        created_at=now,
        updated_by_user_id=user.id,
        updated_at=now,
    )
    session.add(made)
    session.flush()
    return made


def change_rule(
    session: Session,
    sealer: Sealer,
    rule_id: int,
    *,
    user: User,
    now: datetime,
    name: str | None = None,
    description: str | None = None,
    pattern: str | None = None,
    enabled: bool | None = None,
) -> RuleChange:
    rule = _rule(session, rule_id)
    new_name = None if name is None else clean_name(name)
    new_description = None if description is None else clean_description(description)
    if new_name == rule.name:
        new_name = None
    if new_description == rule.description:
        new_description = None
    if pattern is not None and pattern == _opened(sealer, rule.pattern_sealed):
        pattern = None
    if enabled == rule.enabled:
        enabled = None
    if pattern is not None:
        _refuse_pattern(pattern)
    if new_name is not None and _name_taken(session, new_name, other_than=rule.id):
        raise RuleRefused(RuleRefusal.NAME_TAKEN)
    previous_name, previous_enabled = rule.name, rule.enabled
    if new_name is not None:
        rule.name = new_name
    if new_description is not None:
        rule.description = new_description
    if pattern is not None:
        rule.pattern_sealed = _sealed(sealer, pattern)
    if enabled is not None:
        rule.enabled = enabled
    sent = dict(zip(FIELDS, (new_name, new_description, pattern, enabled), strict=True))
    changed = tuple(key for key, value in sent.items() if value is not None)
    if changed:
        rule.updated_by_user_id = user.id
        rule.updated_at = now
        session.flush()
    return RuleChange(rule, changed, previous_name, previous_enabled)


def delete_rule(session: Session, rule_id: int) -> DeletedRule:
    rule = _rule(session, rule_id)
    deleted = DeletedRule(rule.id, rule.name)
    session.delete(rule)
    session.flush()
    return deleted


def export_rules(session: Session, sealer: Sealer) -> list[RuleEntry]:
    rows = session.execute(
        select(
            CustomRule.name, CustomRule.description, CustomRule.pattern_sealed, CustomRule.enabled
        ).order_by(CustomRule.id)
    )
    return [
        RuleEntry.model_construct(
            name=name, description=description, pattern=_opened(sealer, blob), enabled=enabled
        )
        for name, description, blob, enabled in rows
    ]


def check_exchange(format_: str, version: int) -> None:
    if format_ != EXCHANGE_FORMAT or version != EXCHANGE_VERSION:
        raise UnknownExchange


@dataclass(frozen=True)
class CheckedEntries:
    entries: tuple[RuleEntry | None, ...] = field(repr=False)
    refused: tuple[EntryRefusal, ...]


def check_entries(raw: Sequence[object]) -> CheckedEntries:
    if len(raw) > MAX_RULES:
        raise RulesRefused([EntryRefusal(None, RuleRefusal.TOO_MANY)])
    entries: list[RuleEntry | None] = []
    refused: list[EntryRefusal] = []
    for index, item in enumerate(raw):
        try:
            entry = RuleEntry.model_validate(item)
        except ValidationError:
            entries.append(None)
            refused.append(EntryRefusal(index, RuleRefusal.INVALID))
            continue
        entries.append(entry)
        compiled = compile_rule(entry.pattern)
        if isinstance(compiled, RuleRefusal):
            refused.append(EntryRefusal(index, compiled))
    return CheckedEntries(tuple(entries), tuple(refused))


def _file_order(refusal: EntryRefusal) -> tuple[bool, int, bool]:
    return refusal.index is None, refusal.index or 0, refusal.reason is RuleRefusal.NAME_TAKEN


def import_rules(
    session: Session, sealer: Sealer, checked: CheckedEntries, *, user: User, now: datetime
) -> list[CustomRule]:
    refused = list(checked.refused)
    taken = set(session.scalars(select(CustomRule.name)))
    for index, entry in enumerate(checked.entries):
        if entry is None:
            continue
        if entry.name in taken:
            refused.append(EntryRefusal(index, RuleRefusal.NAME_TAKEN))
        taken.add(entry.name)
    if _count(session) + len(checked.entries) > MAX_RULES:
        refused.append(EntryRefusal(None, RuleRefusal.TOO_MANY))
    if refused:
        raise RulesRefused(sorted(refused, key=_file_order))
    made = [
        CustomRule(
            name=entry.name,
            description=entry.description,
            pattern_sealed=_sealed(sealer, entry.pattern),
            enabled=entry.enabled,
            created_by_user_id=user.id,
            created_at=now,
            updated_by_user_id=user.id,
            updated_at=now,
        )
        for entry in checked.entries
        if entry is not None
    ]
    session.add_all(made)
    session.flush()
    return made
