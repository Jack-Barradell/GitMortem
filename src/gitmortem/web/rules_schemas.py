from datetime import datetime
from typing import Annotated, Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    Strict,
    field_validator,
    model_validator,
)

from gitmortem.scanning import rules
from gitmortem.scanning.rule_patterns import RuleRefusal
from gitmortem.scanning.rules import MAX_SAMPLE_CHARS, ExchangeFormat, ExchangeVersion, RuleEntry
from gitmortem.web.schemas import add_model_schemas

_TYPED_TEXT = ConfigDict(extra="forbid", hide_input_in_errors=True, strict=True)


class RuleIn(RuleEntry):
    pass


class RuleChangeIn(BaseModel):
    model_config = _TYPED_TEXT

    name: str | None = None
    description: str | None = None
    pattern: str | None = Field(default=None, repr=False)
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _clean_name(cls, name: str | None) -> str | None:
        return None if name is None else rules.clean_name(name)

    @field_validator("description")
    @classmethod
    def _clean_description(cls, text: str | None) -> str | None:
        return None if text is None else rules.clean_description(text)

    @model_validator(mode="after")
    def _needs_a_field(self) -> Self:
        if all(getattr(self, name) is None for name in rules.FIELDS):
            raise ValueError("send at least one of name, description, pattern and enabled")
        return self


class RuleOut(BaseModel):
    id: int
    name: str
    description: str
    pattern: str = Field(repr=False)
    enabled: bool
    created_by: str | None
    created_at: datetime
    updated_by: str | None
    updated_at: datetime


class RuleListOut(RootModel[list[RuleOut]]):
    pass


class RuleTestIn(BaseModel):
    model_config = _TYPED_TEXT

    pattern: str = Field(repr=False)
    sample: str = Field(repr=False, max_length=MAX_SAMPLE_CHARS)

    @field_validator("sample")
    @classmethod
    def _text(cls, sample: str) -> str:
        rules.check_text(sample)
        return sample


class RuleMatchOut(BaseModel):
    line: int
    start: int
    end: int
    value_start: int
    value_end: int


class RuleTestOut(BaseModel):
    matches: list[RuleMatchOut]


class RuleEntryOut(BaseModel):
    name: str
    description: str
    pattern: str = Field(repr=False)
    enabled: bool


class RulesFileOut(BaseModel):
    format: ExchangeFormat
    version: ExchangeVersion
    rules: list[RuleEntryOut]


class RulesFileIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    format: Annotated[str, Strict()]
    version: Annotated[int, Strict()]
    rules: list[Any] = Field(repr=False)


class RuleRefusedDetail(BaseModel):
    reason: RuleRefusal | None = None
    json_: dict[str, list[str]] | None = Field(default=None, alias="json")


class RuleRefusedOut(BaseModel):
    message: str
    detail: RuleRefusedDetail


class EntryRefusalOut(BaseModel):
    index: int | None
    reason: RuleRefusal


class RulesFileRefusedDetail(BaseModel):
    refused: list[EntryRefusalOut] | None = None


class RulesFileRefusedOut(BaseModel):
    message: str
    detail: RulesFileRefusedDetail


REFUSAL_MODELS: tuple[type[BaseModel], ...] = (RuleRefusedOut, RulesFileRefusedOut)


def add_refusal_schemas(spec: dict[Any, Any] | str) -> dict[Any, Any] | str:
    added: dict[Any, Any] | str = add_model_schemas(spec, REFUSAL_MODELS)
    return added
