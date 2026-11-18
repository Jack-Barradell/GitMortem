import json
from functools import cache
from pathlib import Path
from typing import Any

__all__ = ["RECORD", "recorded_sha256", "recorded_version"]

RECORD = Path(__file__).with_name("known_good.json")


@cache
def _record() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(RECORD.read_text(encoding="utf-8"))
    return loaded


def recorded_version(tool: str) -> str:
    version: str = _record()[tool]["version"]
    return version


def recorded_sha256(tool: str, asset: str) -> str | None:
    sha: str | None = _record()[tool]["sha256"].get(asset)
    return sha
