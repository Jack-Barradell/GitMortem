import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from gitmortem.install import unpack
from gitmortem.install.github import MAX_ASSET_BYTES, Asset, GitHub, NotFound, Release
from gitmortem.install.known_good import recorded_sha256
from gitmortem.install.select import MIN_RELEASE_AGE, Choice, pick
from gitmortem.install.verify import Mismatch, check, file_digest
from gitmortem.scanning import gitleaks, trufflehog
from gitmortem.scanning.git_secrets import KNOWN_BUILDS
from gitmortem.scanning.tools_folder import INSTALLED, folder_problem, recorded_tools

__all__ = [
    "INSTALLED",
    "MAX_BINARY_BYTES",
    "SOURCES",
    "SUPPORTED",
    "Installed",
    "PartlyChanged",
    "Platform",
    "Source",
    "UnsafeFolder",
    "UnsupportedPlatform",
    "install",
    "platform_of",
]

MAX_BINARY_BYTES = 512 << 20
MAX_SUMS_BYTES = 1 << 20
MAX_SCRIPT_BYTES = 1 << 20
GIT_SECRETS_REPO = "awslabs/git-secrets"

type System = Literal["linux", "darwin", "windows"]
type Arch = Literal["x86_64", "arm64"]


@dataclass(frozen=True)
class Platform:
    system: System
    arch: Arch


SUPPORTED: tuple[Platform, ...] = tuple(
    Platform(system, arch)
    for system in ("linux", "darwin", "windows")
    for arch in ("x86_64", "arm64")
)
_SYSTEMS = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
_ARCHES = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


class UnsupportedPlatform(Exception):
    pass


class UnsafeFolder(Exception):
    pass


class PartlyChanged(Exception):
    pass


def _refuse_unsafe(tools_dir: Path) -> None:
    problem = folder_problem(tools_dir)
    if problem is not None:
        raise UnsafeFolder(problem)


def platform_of(system: str, machine: str) -> Platform:
    os_name = _SYSTEMS.get(system.lower())
    arch = _ARCHES.get(machine.lower())
    if os_name is None or arch is None:
        raise UnsupportedPlatform(
            f"no scanner build is installed for {system} on {machine}: "
            "Linux, macOS or Windows on x86_64 or arm64 only"
        )
    return Platform(os_name, arch)  # type: ignore[arg-type]


def _exe(platform: Platform) -> str:
    return ".exe" if platform.system == "windows" else ""


@dataclass(frozen=True)
class Source:
    tool: str
    repo: str
    floor: tuple[int, int, int]
    tested: tuple[int, int, int]
    arches: dict[str, str]
    zip_on_windows: bool

    def asset(self, version: str, platform: Platform) -> tuple[str, Literal["tar.gz", "zip"]]:
        kind: Literal["tar.gz", "zip"] = (
            "zip" if self.zip_on_windows and platform.system == "windows" else "tar.gz"
        )
        arch = self.arches[platform.arch]
        return f"{self.tool}_{version}_{platform.system}_{arch}.{kind}", kind

    def sums(self, version: str) -> str:
        return f"{self.tool}_{version}_checksums.txt"

    def member(self, platform: Platform) -> str:
        return self.tool + _exe(platform)

    def binary(self, platform: Platform) -> str:
        return self.tool + _exe(platform)


SOURCES: dict[str, Source] = {
    "gitleaks": Source(
        "gitleaks",
        "gitleaks/gitleaks",
        gitleaks.FLOOR,
        gitleaks.TESTED,
        {"x86_64": "x64", "arm64": "arm64"},
        zip_on_windows=True,
    ),
    "trufflehog": Source(
        "trufflehog",
        "trufflesecurity/trufflehog",
        trufflehog.FLOOR,
        trufflehog.TESTED,
        {"x86_64": "amd64", "arm64": "arm64"},
        zip_on_windows=False,
    ),
}


@dataclass(frozen=True)
class Installed:
    tool: str
    version: str
    choice: str
    sha256: str
    binary_sha256: str
    newer_than_tested: bool = False
    not_installed: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class _Staged:
    new: Path
    final: Path
    installed: Installed


def _text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def _fetch(github: GitHub, asset: Asset, staging: Path, max_bytes: int) -> Path:
    path = staging / asset.name
    github.download_asset(asset, path, max_bytes=max_bytes)
    return path


def _listed[T](ask: Callable[[], T], repo: str, tool: str) -> T:
    try:
        return ask()
    except NotFound:
        raise NotFound(
            f"GitHub no longer lists {repo}, where {tool} comes from: install {tool} yourself and "
            "name it with --tool-path"
        ) from None


def _stage_release(
    source: Source,
    choice: Choice,
    github: GitHub,
    platform: Platform,
    staging: Path,
    bin_dir: Path,
    record: Callable[[str, str], str | None],
) -> _Staged:
    if choice == "known-good":
        try:
            listing = github.release(source.repo, f"v{_text(source.tested)}")
        except NotFound:
            raise NotFound(
                f"GitHub no longer lists {source.tool} {_text(source.tested)}, the release "
                "GitMortem was tested with: choose latest"
            ) from None
    else:
        listing = _listed(lambda: github.releases(source.repo), source.repo, source.tool)
    release: Release = pick(listing, choice=choice, floor=source.floor, tested=source.tested)
    version = _text(release.version or (0, 0, 0))
    name, kind = source.asset(version, platform)
    archive_asset = release.assets.get(name)
    sums_asset = release.assets.get(source.sums(version))
    if archive_asset is None or sums_asset is None:
        missing = name if archive_asset is None else source.sums(version)
        raise Mismatch(f"{source.tool} {version}: the release has no {missing}")
    sums_path = _fetch(github, sums_asset, staging, MAX_SUMS_BYTES)
    if sums_asset.digest != "sha256:" + file_digest(sums_path, "sha256"):
        raise Mismatch(f"{sums_asset.name}: it does not match GitHub's digest")
    recorded = None
    if choice == "known-good":
        recorded = record(source.tool, name)
        if recorded is None:
            raise Mismatch(f"{name}: GitMortem has no record of the tested release's file")
    archive = _fetch(github, archive_asset, staging, MAX_ASSET_BYTES)
    check(
        archive,
        asset=archive_asset,
        sums=sums_path.read_bytes(),
        algorithm="sha256",
        record=recorded,
    )
    new = staging / f"new-{source.tool}"
    unpack.member(archive, source.member(platform), new, kind=kind, max_bytes=MAX_BINARY_BYTES)
    return _Staged(
        new,
        bin_dir / source.binary(platform),
        Installed(
            source.tool,
            version,
            choice,
            file_digest(archive, "sha256"),
            file_digest(new, "sha256"),
            newer_than_tested=(release.version or (0, 0, 0)) > source.tested,
        ),
    )


def _stage_git_secrets(
    choice: Choice, github: GitHub, staging: Path, bin_dir: Path, builds: dict[str, str]
) -> _Staged:
    known = sorted(
        {version for version in builds.values()},
        key=lambda text: tuple(int(part) for part in text.split(".")),
    )
    listed = _listed(lambda: github.tags(GIT_SECRETS_REPO), GIT_SECRETS_REPO, "git-secrets")
    by_name = {tag.name: tag for tag in listed.tags}
    target = next((by_name[v] for v in reversed(known) if v in by_name), None)
    if target is None or target.version is None:
        raise Mismatch(
            f"git-secrets: none of the builds GitMortem knows ({', '.join(known)}) is tagged"
        )
    newer: list[str] = []
    if choice == "latest":
        for tag in listed.tags:
            if tag.version is None or tag.version <= target.version:
                continue
            published = github.commit_date(GIT_SECRETS_REPO, tag.commit)
            if listed.server_time - published >= MIN_RELEASE_AGE:
                newer.append(tag.name)
    script = staging / "new-git-secrets"
    try:
        github.download(
            github.raw_url(GIT_SECRETS_REPO, target.commit, "git-secrets"),
            script,
            max_bytes=MAX_SCRIPT_BYTES,
        )
    except NotFound:
        raise NotFound(
            f"GitHub no longer serves git-secrets {target.name}'s script at its tagged commit"
        ) from None
    sha = file_digest(script, "sha256")
    if builds.get(sha) != target.name:
        raise Mismatch(f"git-secrets {target.name}: the script is not the build GitMortem knows")
    return _Staged(
        script,
        bin_dir / "git-secrets",
        Installed(
            "git-secrets",
            target.name,
            choice,
            sha,
            sha,
            not_installed=tuple(sorted(newer, key=lambda n: by_name[n].version or (0, 0, 0))),
        ),
    )


def _digest(path: Path) -> str | None:
    try:
        return file_digest(path, "sha256")
    except OSError:
        return None


def _still_good(tools_dir: Path, platform: Platform, choice: Choice) -> bool:
    bin_dir = tools_dir / "bin"
    recorded = recorded_tools(tools_dir)
    for source in SOURCES.values():
        entry = recorded.get(source.tool)
        if entry is None or _digest(bin_dir / source.binary(platform)) != entry.binary_sha256:
            return False
        if choice == "known-good" and entry.version != _text(source.tested):
            return False
    entry = recorded.get("git-secrets")
    held = _digest(bin_dir / "git-secrets")
    return entry is not None and held == entry.binary_sha256 and held in KNOWN_BUILDS


def install(
    tools_dir: Path,
    choice: Choice,
    *,
    github: GitHub,
    platform: Platform,
    if_missing: bool = False,
    folder_mode: int = 0o700,
) -> list[Installed]:
    bin_dir = tools_dir / "bin"
    _refuse_unsafe(tools_dir)
    if if_missing and _still_good(tools_dir, platform, choice):
        return []
    for folder in (tools_dir, bin_dir):
        if not folder.is_dir():
            folder.mkdir(mode=folder_mode, parents=True)
            folder.chmod(folder_mode)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=tools_dir))
    try:
        staged = [
            _stage_release(source, choice, github, platform, staging, bin_dir, recorded_sha256)
            for source in SOURCES.values()
        ]
        staged.append(_stage_git_secrets(choice, github, staging, bin_dir, KNOWN_BUILDS))
        done = [item.installed for item in staged]
        record = _staged_record(staging, done)
        _place_all(
            [
                *((item.new, item.final, 0o755) for item in staged),
                (record, tools_dir / INSTALLED, 0o644),
            ],
            staging,
        )
        return done
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(staging)


def _staged_record(staging: Path, done: Sequence[Installed]) -> Path:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {"tools": [{**asdict(item), "installed_at": now} for item in done]}
    staged = staging / f"new-{INSTALLED}"
    staged.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return staged


def _place_all(placing: Sequence[tuple[Path, Path, int]], staging: Path) -> None:
    moved: list[tuple[Path, Path | None]] = []
    try:
        for new, final, mode in placing:
            kept = None
            if os.path.lexists(final):
                kept = staging / f"old-{final.name}"
                os.replace(final, kept)
            moved.append((final, kept))
            new.chmod(mode)
            os.replace(new, final)
    except OSError as exc:
        left = _put_back(moved)
        if left:
            raise PartlyChanged(
                f"{exc}; these could not be put back as they were: {', '.join(left)}"
            ) from exc
        raise


def _put_back(moved: Sequence[tuple[Path, Path | None]]) -> list[str]:
    left: list[str] = []
    for final, kept in reversed(moved):
        try:
            if kept is None:
                final.unlink(missing_ok=True)
            else:
                os.replace(kept, final)
        except OSError:
            left.append(final.name)
    return left
