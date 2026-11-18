from collections.abc import Iterable, Mapping
from enum import StrEnum
from importlib import resources
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    Strict,
    WithJsonSchema,
)

from gitmortem.db.models import AuditValue, ToolName
from gitmortem.scanning import versions
from gitmortem.scanning.gitleaks_config import STOCK_RULE_IDS


def _detector_names() -> tuple[str, ...]:
    data = resources.files("gitmortem.scanning").joinpath("data", versions.DETECTOR_LIST)
    text = data.read_text("ascii")
    return tuple(text.splitlines())


DETECTOR_NAMES: tuple[str, ...] = _detector_names()
_DETECTORS_BY_KEY: Mapping[str, str] = {name.lower(): name for name in DETECTOR_NAMES}


def _versions(names: Iterable[str]) -> dict[str, frozenset[str]]:
    found: dict[str, set[str]] = {}
    for name in names:
        kind = name.split(".", 1)[0]
        found.setdefault(kind, set())
        if kind != name:
            found[kind].add(name)
    return {kind: frozenset(versions) for kind, versions in found.items()}


_VERSIONS: Mapping[str, frozenset[str]] = _versions(DETECTOR_NAMES)
RULE_IDS: tuple[str, ...] = tuple(sorted(STOCK_RULE_IDS))


def canonical_detector(name: str) -> str:
    found = _DETECTORS_BY_KEY.get(name.lower())
    if found is None:
        raise ValueError("not a detector TruffleHog implements")
    return found


def _stock_rules(ids: frozenset[str]) -> frozenset[str]:
    if not ids <= STOCK_RULE_IDS:
        raise ValueError("not a rule id of the stock gitleaks config")
    return ids


def _detectors(names: frozenset[str]) -> frozenset[str]:
    return frozenset(canonical_detector(name) for name in names)


def _sorted(names: Iterable[str]) -> list[str]:
    return sorted(names)


def _choices(vocabulary: Iterable[str]) -> dict[str, Any]:
    return {
        "type": "array",
        "uniqueItems": True,
        "items": {"type": "string", "enum": list(vocabulary)},
    }


Switch = Annotated[bool, Strict()]
RuleIds = Annotated[
    frozenset[Annotated[str, Strict()]],
    AfterValidator(_stock_rules),
    PlainSerializer(_sorted, return_type=list[str]),
    WithJsonSchema(_choices(RULE_IDS)),
]
DetectorNames = Annotated[
    frozenset[Annotated[str, Strict()]],
    AfterValidator(_detectors),
    PlainSerializer(_sorted, return_type=list[str]),
    WithJsonSchema(_choices(DETECTOR_NAMES)),
]


class ToolOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class GitSecretsOptions(ToolOptions):
    allow_aws_examples: Switch = False


class GitleaksOptions(ToolOptions):
    skip_paths: Switch = False
    skip_placeholders: Switch = False
    skip_stopwords: Switch = False
    skip_rule_allowlists: Switch = False
    rules_off: RuleIds = frozenset()
    scan_merges: Switch = True
    max_decode_depth: Annotated[int, Strict(), Field(ge=0, le=10)] = 5
    max_archive_depth: Annotated[int, Strict(), Field(ge=0, le=10)] = 3
    max_target_megabytes: Annotated[int, Strict(), Field(ge=0, le=10_240)] = 0


class TruffleHogOptions(ToolOptions):
    hide_word_filtered: Switch = False
    filter_entropy: Annotated[float, Strict(), Field(ge=0.0, le=8.0, allow_inf_nan=False)] = 0.0
    filter_unverified: Switch = False
    detectors_off: DetectorNames = frozenset()
    skip_binaries: Switch = False
    skip_archives: Switch = False
    detector_timeout_seconds: Annotated[int, Strict(), Field(ge=1, le=300)] = 10


class CustomRulesOptions(ToolOptions):
    pass


RuleId = Annotated[int, Strict(), Field(ge=1)]


class CustomRulesRun(CustomRulesOptions):
    rules: tuple[RuleId, ...]


OPTIONS: Mapping[ToolName, type[ToolOptions]] = {
    ToolName.GIT_SECRETS: GitSecretsOptions,
    ToolName.GITLEAKS: GitleaksOptions,
    ToolName.TRUFFLEHOG: TruffleHogOptions,
    ToolName.CUSTOM_RULES: CustomRulesOptions,
}

OptionValue = bool | int | float | list[str]


def options_model(tool: ToolName) -> type[ToolOptions]:
    return OPTIONS[tool]


def run_options_model(tool: ToolName) -> type[ToolOptions]:
    return CustomRulesRun if tool is ToolName.CUSTOM_RULES else OPTIONS[tool]


def no_rules(options: ToolOptions) -> bool:
    if isinstance(options, CustomRulesRun):
        return not options.rules
    if isinstance(options, GitleaksOptions):
        return options.rules_off >= STOCK_RULE_IDS
    if isinstance(options, TruffleHogOptions):
        off = options.detectors_off
        return all(
            kind in off or (bool(versions) and versions <= off)
            for kind, versions in _VERSIONS.items()
        )
    return False


def options_json(options: ToolOptions) -> dict[str, Any]:
    return options.model_dump(mode="json")


def option_changes(before: ToolOptions, after: ToolOptions) -> dict[str, AuditValue]:
    old, new = options_json(before), options_json(after)
    return {name: [old[name], new[name]] for name in old if old[name] != new[name]}


OptionName = StrEnum(  # type: ignore[misc]
    "OptionName",
    {name: name for model in OPTIONS.values() for name in model.model_fields},
)


class OptionKind(StrEnum):
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    CHOICES = "choices"


_KINDS: Mapping[str, OptionKind] = {
    "boolean": OptionKind.BOOL,
    "integer": OptionKind.INT,
    "number": OptionKind.FLOAT,
    "array": OptionKind.CHOICES,
}


class NotATypedOption(TypeError):
    def __init__(self, name: str) -> None:
        super().__init__(f"option {name!r} is not a switch, a bounded number or a fixed choice")


def option_descriptors(model: type[ToolOptions]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for name, schema in model.model_json_schema()["properties"].items():
        kind = _KINDS.get(schema.get("type", ""))
        if kind is None:
            raise NotATypedOption(name)
        descriptor: dict[str, Any] = {"name": name, "kind": kind, "default": schema["default"]}
        if kind in (OptionKind.INT, OptionKind.FLOAT):
            if "minimum" not in schema or "maximum" not in schema:
                raise NotATypedOption(name)
            descriptor["min"], descriptor["max"] = schema["minimum"], schema["maximum"]
        if kind is OptionKind.CHOICES:
            choices = schema.get("items", {}).get("enum")
            if not choices:
                raise NotATypedOption(name)
            descriptor["choices"] = list(choices)
        found.append(descriptor)
    return found
