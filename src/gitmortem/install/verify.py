import hashlib
import re
from pathlib import Path
from typing import Literal

from gitmortem.install.github import Asset

__all__ = ["Mismatch", "check", "file_digest", "sums_line"]

_LINE = re.compile(r"^([0-9a-f]+) [ *](.+)$")
_LENGTHS = {"sha256": 64, "sha512": 128}


class Mismatch(Exception):
    pass


def file_digest(path: Path, algorithm: Literal["sha256", "sha512"]) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, algorithm).hexdigest()


def sums_line(sums: bytes, name: str, algorithm: Literal["sha256", "sha512"]) -> str:
    found = []
    for line in sums.decode("utf-8", "replace").splitlines():
        match = _LINE.match(line.strip())
        if match and match.group(2) == name and len(match.group(1)) == _LENGTHS[algorithm]:
            found.append(match.group(1))
    if len(found) != 1:
        raise Mismatch(f"{name}: the vendor's checksum file has {len(found)} lines for it, not 1")
    return found[0]


def check(
    path: Path,
    *,
    asset: Asset,
    sums: bytes,
    algorithm: Literal["sha256", "sha512"],
    record: str | None,
) -> None:
    if asset.digest is None or not asset.digest.startswith("sha256:"):
        raise Mismatch(f"{asset.name}: GitHub reports no SHA-256 digest for it")
    sha256 = file_digest(path, "sha256")
    if asset.digest.removeprefix("sha256:") != sha256:
        raise Mismatch(f"{asset.name}: it does not match GitHub's digest")
    listed = sums_line(sums, asset.name, algorithm)
    own = sha256 if algorithm == "sha256" else file_digest(path, algorithm)
    if listed != own:
        raise Mismatch(f"{asset.name}: it does not match the vendor's checksum")
    if record is not None and record != sha256:
        raise Mismatch(f"{asset.name}: it does not match GitMortem's record of the tested release")
