import json
import os
import stat
import sys
from collections.abc import Collection, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from gitmortem import privacy
from gitmortem.db.models import ToolName
from gitmortem.scanning.tools import Detection, DetectionStatus

__all__ = [
    "INSTALLED",
    "MAX_RECORD_BYTES",
    "Recorded",
    "folder_problem",
    "judged",
    "recorded_tools",
]

INSTALLED = "installed.json"
MAX_RECORD_BYTES = 64 << 10
_HINT = "name a folder of your own with --tools-dir"
_JUDGED = frozenset({DetectionStatus.FOUND, DetectionStatus.UNTESTED})


def folder_problem(folder: Path) -> str | None:
    for each in (folder, folder / "bin"):
        try:
            held = each.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            return f"{each} cannot be read ({exc.strerror}): {_HINT}"
        if not stat.S_ISDIR(held.st_mode):
            return f"{each} is not a folder: {_HINT}"
        if sys.platform == "win32":
            try:
                privacy.require_private(each, "tools folder", reading=False, hint=_HINT)
            except privacy.NotPrivate as exc:
                return str(exc)
            continue
        if held.st_uid not in {os.geteuid(), 0}:
            return f"{each} is owned by another user: {_HINT}"
        if held.st_mode & 0o022:
            return (
                f"{each} is writable by others than its owner, who could swap a scanner: "
                f"run chmod go-w {each}, or {_HINT}"
            )
    return None


@dataclass(frozen=True)
class Recorded:
    version: str | None
    binary_sha256: str


def recorded_tools(folder: Path) -> dict[str, Recorded]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(folder / INSTALLED, flags | getattr(os, "O_BINARY", 0))
    except OSError:
        return {}
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode) or held.st_size > MAX_RECORD_BYTES:
            return {}
        data = os.read(fd, MAX_RECORD_BYTES + 1)
    except OSError:
        return {}
    finally:
        os.close(fd)
    if len(data) > MAX_RECORD_BYTES:
        return {}
    try:
        record = json.loads(data)
    except ValueError:
        return {}
    tools = record.get("tools") if isinstance(record, dict) else None
    if not isinstance(tools, list):
        return {}
    return {
        item["tool"]: Recorded(
            item["version"] if isinstance(item.get("version"), str) else None,
            item["binary_sha256"],
        )
        for item in tools
        if isinstance(item, dict)
        and isinstance(item.get("tool"), str)
        and isinstance(item.get("binary_sha256"), str)
    }


def _inside(path: Path, folder: Path) -> bool:
    try:
        return os.path.samefile(path.parent, folder)
    except OSError:
        return False


def in_bin(path: Path, bin_dir: Path) -> bool:
    return _inside(path, bin_dir)


def judged(
    found: Mapping[ToolName, Detection], folder: Path, *, by_build: Collection[ToolName]
) -> dict[ToolName, Detection]:
    bin_dir = folder / "bin"
    problem = folder_problem(folder)
    recorded = {} if problem is not None else recorded_tools(folder)
    out: dict[ToolName, Detection] = {}
    for name, detection in found.items():
        if detection.path is None or not _inside(detection.path, bin_dir):
            out[name] = detection
        elif problem is not None:
            out[name] = replace(detection, status=DetectionStatus.UNSAFE_FOLDER)
        elif (
            name not in by_build
            and detection.status in _JUDGED
            and (
                name.value not in recorded or detection.sha256 != recorded[name.value].binary_sha256
            )
        ):
            out[name] = replace(detection, status=DetectionStatus.UNRECOGNISED)
        else:
            out[name] = detection
    return out
