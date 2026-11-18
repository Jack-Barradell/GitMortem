import contextlib
import ipaddress
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPMessage, HTTPResponse
from pathlib import Path
from typing import IO, Any
from urllib.parse import quote, urlsplit

from gitmortem import __version__

__all__ = [
    "API",
    "LATEST_PAGE",
    "MAX_API_BYTES",
    "MAX_ASSET_BYTES",
    "RAW",
    "REQUEST_SECONDS",
    "Asset",
    "BadReply",
    "GitHub",
    "GitHubError",
    "GitHubRateLimited",
    "GitHubUnreachable",
    "InsecureAddress",
    "Listing",
    "NotFound",
    "Release",
    "Tag",
    "TagListing",
    "TooLarge",
    "version_of",
]

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
REQUEST_SECONDS = 60
MAX_API_BYTES = 16 << 20
LATEST_PAGE = 30
MAX_ASSET_BYTES = 256 << 20
MAX_REDIRECTS = 5
_BLOCK = 64 << 10
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
_NEW_FILE |= getattr(os, "O_BINARY", 0)
_LOOPBACK_NAMES = frozenset({"localhost"})


class GitHubError(Exception):
    pass


class GitHubUnreachable(GitHubError):
    pass


class GitHubRateLimited(GitHubError):
    pass


class TooLarge(GitHubError):
    pass


class BadReply(GitHubError):
    pass


class NotFound(BadReply):
    pass


class InsecureAddress(GitHubError):
    pass


def version_of(tag: str) -> tuple[int, int, int] | None:
    found = _VERSION.match(tag)
    if found is None:
        return None
    major, minor, patch = (int(part) for part in found.groups())
    return major, minor, patch


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int
    digest: str | None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class Release:
    tag: str
    version: tuple[int, int, int] | None
    published_at: datetime | None
    draft: bool
    prerelease: bool
    assets: Mapping[str, Asset]

    @property
    def settled_at(self) -> datetime | None:
        if self.published_at is None:
            return None
        changed = [asset.updated_at for asset in self.assets.values() if asset.updated_at]
        return max([self.published_at, *changed])


@dataclass(frozen=True)
class Listing:
    releases: list[Release]
    server_time: datetime


@dataclass(frozen=True)
class Tag:
    name: str
    commit: str
    version: tuple[int, int, int] | None


@dataclass(frozen=True)
class TagListing:
    tags: list[Tag]
    server_time: datetime


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def tls_context(cafile: Path | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=None if cafile is None else str(cafile))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _check_address(url: str, *, loopback_http: bool) -> None:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https" and host:
        return
    if loopback_http and parts.scheme == "http" and _is_loopback(host):
        return
    raise InsecureAddress(f"{parts.scheme or 'no scheme'}://{host}: only HTTPS is used")


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, *, loopback_http: bool) -> None:
        super().__init__()
        self.loopback_http = loopback_http

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        _check_address(newurl, loopback_http=self.loopback_http)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _time(text: object) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


class GitHub:
    def __init__(
        self, api: str = API, raw: str = RAW, *, allow_loopback_http: bool = False
    ) -> None:
        self._loopback_http = allow_loopback_http
        _check_address(api, loopback_http=allow_loopback_http)
        _check_address(raw, loopback_http=allow_loopback_http)
        self.api = api.rstrip("/")
        self.raw = raw.rstrip("/")
        self._opener = urllib.request.build_opener(
            _Redirects(loopback_http=allow_loopback_http),
            urllib.request.HTTPSHandler(context=tls_context()),
        )
        self._headers = {"User-Agent": f"gitmortem-installer/{__version__}"}

    def _open(self, url: str) -> HTTPResponse:
        _check_address(url, loopback_http=self._loopback_http)
        host = urlsplit(url).hostname or ""
        request = urllib.request.Request(url, headers=self._headers)  # noqa: S310
        try:
            response: HTTPResponse = self._opener.open(request, timeout=REQUEST_SECONDS)
        except urllib.error.HTTPError as error:
            remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
            if error.code == 429 or (error.code == 403 and remaining == "0"):
                reset = error.headers.get("X-RateLimit-Reset", "") if error.headers else ""
                when = ""
                if reset.isdigit():
                    when = f", until {datetime.fromtimestamp(int(reset), UTC):%Y-%m-%d %H:%M} UTC"
                raise GitHubRateLimited(
                    f"{host} refused the request: rate limit reached{when}"
                ) from None
            if error.code == 404:
                raise NotFound(f"{host} answered 404") from None
            raise BadReply(f"{host} answered {error.code}") from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, InsecureAddress):
                raise error.reason from None
            reason = getattr(error.reason, "strerror", None) or type(error.reason).__name__
            raise GitHubUnreachable(f"{host} could not be reached: {reason}") from None
        except InsecureAddress:
            raise
        except OSError as error:
            raise GitHubUnreachable(
                f"{host} could not be reached: {type(error).__name__}"
            ) from None
        return response

    def _json(self, url: str) -> tuple[Any, HTTPResponse]:
        with self._open(url) as response:
            body = response.read(MAX_API_BYTES + 1)
        if len(body) > MAX_API_BYTES:
            raise TooLarge(f"{urlsplit(url).hostname} sent a reply over {MAX_API_BYTES} bytes")
        try:
            return json.loads(body), response
        except ValueError:
            raise BadReply(f"{urlsplit(url).hostname} sent a reply that is not JSON") from None

    def _dated(self, url: str) -> tuple[Any, datetime | None]:
        found, response = self._json(url)
        date = response.headers.get("Date")
        try:
            server_time = parsedate_to_datetime(date) if date else None
        except (TypeError, ValueError):
            server_time = None
        return found, server_time

    def json_document(self, url: str) -> tuple[Any, datetime]:
        found, server_time = self._dated(url)
        if server_time is None:
            raise BadReply(f"{urlsplit(url).hostname} sent no date")
        return found, server_time

    def _listed(self, url: str) -> tuple[list[Any], datetime]:
        found, server_time = self._dated(url)
        if server_time is None or not isinstance(found, list):
            raise BadReply(f"{urlsplit(url).hostname} sent no list with a date")
        return found, server_time

    def releases(self, repo: str) -> Listing:
        url = f"{self.api}/repos/{quote(repo)}/releases?per_page={LATEST_PAGE}"
        found, server_time = self._listed(url)
        return Listing([_release(item) for item in found if isinstance(item, dict)], server_time)

    def release(self, repo: str, tag: str) -> Listing:
        url = f"{self.api}/repos/{quote(repo)}/releases/tags/{quote(tag)}"
        found, server_time = self._dated(url)
        if server_time is None or not isinstance(found, dict):
            raise BadReply(f"{urlsplit(url).hostname} sent no release with a date")
        return Listing([_release(found)], server_time)

    def tags(self, repo: str) -> TagListing:
        found, server_time = self._listed(f"{self.api}/repos/{quote(repo)}/tags?per_page=100")
        tags = []
        for item in found:
            name = item.get("name") if isinstance(item, dict) else None
            commit = item.get("commit") if isinstance(item, dict) else None
            sha = commit.get("sha") if isinstance(commit, dict) else None
            if isinstance(name, str) and isinstance(sha, str) and re.fullmatch("[0-9a-f]{40}", sha):
                tags.append(Tag(name, sha, version_of(name)))
        return TagListing(tags, server_time)

    def commit_date(self, repo: str, commit: str) -> datetime:
        found, _ = self._json(f"{self.api}/repos/{quote(repo)}/commits/{quote(commit)}")
        committer = (
            (found.get("commit") or {}).get("committer") if isinstance(found, dict) else None
        )
        date = _time(committer.get("date")) if isinstance(committer, dict) else None
        if date is None:
            raise BadReply(f"{urlsplit(self.api).hostname} sent no commit date")
        return date

    def raw_url(self, repo: str, commit: str, path: str) -> str:
        return f"{self.raw}/{quote(repo)}/{quote(commit)}/{quote(path)}"

    def download_asset(self, asset: Asset, dest: Path, *, max_bytes: int = MAX_ASSET_BYTES) -> None:
        if asset.size > max_bytes:
            raise TooLarge(
                f"{asset.name} is listed at {asset.size} bytes, "
                f"over the {max_bytes} GitMortem accepts"
            )
        self.download(asset.url, dest, max_bytes=asset.size)

    def download(self, url: str, dest: Path, *, max_bytes: int) -> None:
        fd = os.open(dest, _NEW_FILE, 0o600)
        written = 0
        try:
            with os.fdopen(fd, "wb") as out, self._open(url) as response:
                while block := response.read(_BLOCK):
                    written += len(block)
                    if written > max_bytes:
                        raise TooLarge(f"{urlsplit(url).hostname} sent more than {max_bytes} bytes")
                    out.write(block)
        except BaseException:
            with contextlib.suppress(OSError):
                dest.unlink()
            raise


def _release(item: Mapping[str, Any]) -> Release:
    tag = item.get("tag_name")
    tag = tag if isinstance(tag, str) else ""
    assets: dict[str, Asset] = {}
    for entry in item.get("assets") or []:
        if not isinstance(entry, dict):
            continue
        name, url, size = entry.get("name"), entry.get("browser_download_url"), entry.get("size")
        digest = entry.get("digest")
        if isinstance(name, str) and isinstance(url, str) and isinstance(size, int):
            assets[name] = Asset(
                name,
                url,
                size,
                digest if isinstance(digest, str) else None,
                _time(entry.get("updated_at")),
            )
    return Release(
        tag=tag,
        version=version_of(tag),
        published_at=_time(item.get("published_at")),
        draft=item.get("draft") is True,
        prerelease=item.get("prerelease") is True,
        assets=assets,
    )
