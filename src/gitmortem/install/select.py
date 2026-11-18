from datetime import timedelta
from typing import Literal

from gitmortem.install.github import Listing, Release

__all__ = ["MIN_RELEASE_AGE", "Choice", "NoRelease", "pick"]

MIN_RELEASE_AGE = timedelta(days=7)

type Choice = Literal["known-good", "latest"]


class NoRelease(Exception):
    pass


def _text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def pick(
    listing: Listing,
    *,
    choice: Choice,
    floor: tuple[int, int, int],
    tested: tuple[int, int, int],
) -> Release:
    stable = [
        release
        for release in listing.releases
        if not release.draft
        and not release.prerelease
        and release.version is not None
        and release.published_at is not None
    ]
    if choice == "known-good":
        for release in stable:
            if release.version == tested:
                return release
        raise NoRelease(f"the tested release {_text(tested)} is not among the published ones")
    aged = [
        release
        for release in stable
        if release.version is not None
        and (settled := release.settled_at) is not None
        and release.version[0] == tested[0]
        and release.version >= floor
        and listing.server_time - settled >= MIN_RELEASE_AGE
    ]
    if not aged:
        raise NoRelease(
            f"no release of {tested[0]}.x at or above {_text(floor)} is at least "
            f"{MIN_RELEASE_AGE.days} days old"
        )
    return max(aged, key=lambda release: release.version or (0, 0, 0))
