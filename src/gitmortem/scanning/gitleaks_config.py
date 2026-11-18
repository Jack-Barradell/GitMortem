import copy
import functools
import tomllib
from collections.abc import Mapping
from importlib import resources
from typing import TYPE_CHECKING, Any

import tomli_w

from gitmortem.scanning.versions import STOCK_CONFIG

if TYPE_CHECKING:
    from gitmortem.scanning.options import GitleaksOptions

_GLOBAL_KEYS: Mapping[str, str] = {
    "paths": "skip_paths",
    "regexes": "skip_placeholders",
    "stopwords": "skip_stopwords",
}
_RULE_KEYS: Mapping[str, str] = {
    "stopwords": "skip_stopwords",
    "regexes": "skip_rule_allowlists",
    "paths": "skip_rule_allowlists",
    "regexTarget": "skip_rule_allowlists",
    "condition": "skip_rule_allowlists",
}
_DESCRIPTION = "description"
_EITHER = frozenset({"", "OR", "||"})
_CHECKS = frozenset({"commits", "paths", "regexes", "stopwords"})
_TOP_KEYS = frozenset({"title", "minVersion", "allowlist", "rules"})
_RULE_FIELDS = frozenset(
    {"id", "description", "regex", "entropy", "keywords", "path", "secretGroup", "allowlists"}
)


class NoRulesEnabled(ValueError):
    def __init__(self) -> None:
        super().__init__("every gitleaks rule is turned off")


class UnknownConfigKey(ValueError):
    def __init__(self, where: str, key: str) -> None:
        super().__init__(f"the stock gitleaks config has an unknown key in {where}: {key}")


class MixedAllowlist(ValueError):
    def __init__(self, where: str) -> None:
        super().__init__(
            f"the stock gitleaks config has an AND allowlist across families in {where}"
        )


def stock_bytes() -> bytes:
    return resources.files("gitmortem.scanning").joinpath("data", STOCK_CONFIG).read_bytes()


@functools.cache
def _stock() -> dict[str, Any]:
    return tomllib.loads(stock_bytes().decode("utf-8"))


STOCK_RULE_IDS: frozenset[str] = frozenset(rule["id"] for rule in _stock()["rules"])


def build_config(options: "GitleaksOptions") -> bytes:
    return tomli_w.dumps(generate(_stock(), options)).encode("utf-8")


def generate(stock: Mapping[str, Any], options: "GitleaksOptions") -> dict[str, Any]:
    for key in stock:
        if key not in _TOP_KEYS:
            raise UnknownConfigKey("the config", key)
    rules = [_rule(rule, options) for rule in stock["rules"] if rule["id"] not in options.rules_off]
    if not rules:
        raise NoRulesEnabled
    config = {key: value for key, value in stock.items() if key not in ("allowlist", "rules")}
    found = stock.get("allowlist")
    allowlist = None if found is None else _kept(found, _GLOBAL_KEYS, options, "the allowlist")
    if allowlist is not None:
        config["allowlist"] = allowlist
    config["rules"] = rules
    return copy.deepcopy(config)


def _rule(rule: Mapping[str, Any], options: "GitleaksOptions") -> dict[str, Any]:
    for key in rule:
        if key not in _RULE_FIELDS:
            raise UnknownConfigKey("a rule", key)
    kept = {key: value for key, value in rule.items() if key != "allowlists"}
    allowlists = [
        allowlist
        for found in rule.get("allowlists", ())
        if (allowlist := _kept(found, _RULE_KEYS, options, "a rule allowlist")) is not None
    ]
    if allowlists:
        kept["allowlists"] = allowlists
    return kept


def _kept(
    allowlist: Mapping[str, Any],
    families: Mapping[str, str],
    options: "GitleaksOptions",
    where: str,
) -> dict[str, Any] | None:
    kept: dict[str, Any] = {}
    for key, value in allowlist.items():
        if key == _DESCRIPTION:
            kept[key] = value
        elif key not in families:
            raise UnknownConfigKey(where, key)
        elif getattr(options, families[key]):
            kept[key] = value
    spanned = {families[key] for key in _CHECKS & allowlist.keys()}
    if str(allowlist.get("condition", "")).upper() not in _EITHER and len(spanned) > 1:
        raise MixedAllowlist(where)
    return kept if _CHECKS & kept.keys() else None
