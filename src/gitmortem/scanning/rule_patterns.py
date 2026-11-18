import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

import re2

__all__ = [
    "MAX_PATTERN_CHARS",
    "MAX_PROGRAM_SIZE",
    "PROBE_MAX_MEM",
    "RE2_MAX_MEM",
    "RUN_MAX_MEM",
    "VALUE_GROUP",
    "CompiledMatch",
    "CompiledRule",
    "RuleRefusal",
    "StoredRule",
    "compile_rule",
    "run_budget",
    "scan_options",
]

MAX_PATTERN_CHARS = 4_096
MAX_PROGRAM_SIZE = 8_192
RE2_MAX_MEM = 64 << 20
RUN_MAX_MEM = 1 << 30
PROBE_MAX_MEM = 1 << 20
_TOO_LARGE = b"pattern too large - compile failed"
VALUE_GROUP = "value"
_VALUE_OPENER = re.compile(r"\(\?P?<value>")


class CompiledMatch(Protocol):
    def span(self, group: int = 0) -> tuple[int, int]: ...


class CompiledRule(Protocol):
    @property
    def groupindex(self) -> Mapping[str, int]: ...

    @property
    def groups(self) -> int: ...

    @property
    def programsize(self) -> int: ...

    def search(self, text: str) -> CompiledMatch | None: ...

    def finditer(self, text: str) -> Iterator[CompiledMatch]: ...


class RuleRefusal(StrEnum):
    TOO_LONG = "too_long"
    DOES_NOT_COMPILE = "does_not_compile"
    TOO_COMPLEX = "too_complex"
    BAD_VALUE_GROUP = "bad_value_group"
    NAME_TAKEN = "name_taken"
    TOO_MANY = "too_many"
    INVALID = "invalid"


@dataclass(frozen=True)
class StoredRule:
    id: int
    name: str
    pattern: str = field(repr=False)


def scan_options() -> Any:
    return _options(RE2_MAX_MEM)


def _options(max_mem: int) -> Any:
    options = re2.Options()
    options.max_mem = max_mem
    options.log_errors = False
    options.never_nl = True
    options.encoding = re2.Options.Encoding.UTF8
    return options


def _compiled(pattern: str, max_mem: int) -> tuple[CompiledRule | None, bool]:
    try:
        return re2._Regexp(pattern, _options(max_mem)), False
    except re2.error as refused:
        return None, refused.args == (_TOO_LARGE,)


def run_budget(rules: int) -> int:
    return max(PROBE_MAX_MEM, min(RE2_MAX_MEM, RUN_MAX_MEM // max(rules, 1)))


def compile_rule(pattern: str, *, max_mem: int | None = None) -> CompiledRule | RuleRefusal:
    if len(pattern) > MAX_PATTERN_CHARS:
        return RuleRefusal.TOO_LONG
    try:
        pattern.encode()
    except UnicodeEncodeError:
        return RuleRefusal.DOES_NOT_COMPILE
    probe, too_large = _compiled(pattern, PROBE_MAX_MEM)
    if probe is None:
        return RuleRefusal.TOO_COMPLEX if too_large else RuleRefusal.DOES_NOT_COMPILE
    if probe.programsize > MAX_PROGRAM_SIZE:
        return RuleRefusal.TOO_COMPLEX
    if not _value_group_only(pattern, probe):
        return RuleRefusal.BAD_VALUE_GROUP
    compiled, _ = _compiled(pattern, RE2_MAX_MEM if max_mem is None else max_mem)
    return RuleRefusal.TOO_COMPLEX if compiled is None else compiled


def _value_group_only(pattern: str, probe: CompiledRule) -> bool:
    if not probe.groupindex:
        return True
    if set(probe.groupindex) != {VALUE_GROUP}:
        return False
    openers = 0

    def renamed(opener: re.Match[str]) -> str:
        nonlocal openers
        openers += 1
        return opener.group(0).replace(VALUE_GROUP, f"v{openers}")

    asked, _ = _compiled(_VALUE_OPENER.sub(renamed, pattern), PROBE_MAX_MEM)
    if asked is None:
        return False
    names = set(asked.groupindex)
    return len(names) == 1 and names <= {f"v{n}" for n in range(1, openers + 1)}
