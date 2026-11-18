import argparse
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, ValidationError

from gitmortem.gitrun import GitError, GitRunner, GitTimeout
from gitmortem.scanning import rules_walk
from gitmortem.scanning.rule_patterns import StoredRule

__all__ = [
    "EXIT_BAD_RULES",
    "EXIT_TIMED_OUT",
    "EXIT_UNREADABLE",
    "EXIT_WALKED",
    "main",
    "read_rules",
    "walk",
]

EXIT_WALKED = rules_walk.CHILD_WALKED
EXIT_TIMED_OUT = rules_walk.CHILD_TIMED_OUT
EXIT_UNREADABLE = rules_walk.CHILD_UNREADABLE
EXIT_BAD_RULES = rules_walk.CHILD_BAD_RULES


class _Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    id: StrictInt
    name: StrictStr
    pattern: StrictStr


class _Rules(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    rules: list[_Rule]


def read_rules(stdin: BinaryIO) -> list[StoredRule] | None:
    try:
        sent = _Rules.model_validate_json(stdin.read())
    except ValidationError:
        return None
    if not sent.rules:
        return None
    return [StoredRule(id=rule.id, name=rule.name, pattern=rule.pattern) for rule in sent.rules]


def walk(
    runner: GitRunner,
    shadow: Path,
    hits: Path,
    rule_set: rules_walk.RuleSet,
    left_out: int,
    *,
    timeout: float,
    merge_held_bytes: int,
) -> int:
    try:
        rules_walk.write_hits_file(
            runner,
            shadow,
            hits,
            rule_set,
            left_out,
            timeout=timeout,
            cancel=threading.Event(),
            merge_held_bytes=merge_held_bytes,
        )
    except GitTimeout:
        return EXIT_TIMED_OUT
    except GitError:
        return EXIT_UNREADABLE
    return EXIT_WALKED


def main(argv: Sequence[str], stdin: BinaryIO) -> int:
    parser = argparse.ArgumentParser(prog="gitmortem.scanning.rules_child", add_help=False)
    parser.add_argument("--shadow", type=Path, required=True)
    parser.add_argument("--hits", type=Path, required=True)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--merge-held-bytes", type=int, required=True)
    parser.add_argument("--left-out", type=int, required=True)
    args = parser.parse_args(list(argv))
    stored = read_rules(stdin)
    if stored is None:
        return EXIT_BAD_RULES
    rule_set, refused = rules_walk.compile_rule_set(stored)
    if rule_set is None:
        return EXIT_BAD_RULES
    return walk(
        GitRunner(args.private),
        args.shadow,
        args.hits,
        rule_set,
        args.left_out + refused,
        timeout=args.timeout,
        merge_held_bytes=args.merge_held_bytes,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:], sys.stdin.buffer))
