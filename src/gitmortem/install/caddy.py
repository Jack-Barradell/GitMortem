import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gitmortem.install import unpack
from gitmortem.install.github import GitHub, tls_context
from gitmortem.install.select import NoRelease, pick
from gitmortem.install.verify import Mismatch, check, file_digest, sums_line

__all__ = [
    "CADDY_FLOOR",
    "HTTPS_WAIT_SECONDS",
    "INTERNAL_ROOT",
    "TLS_CERT",
    "TLS_KEY",
    "NoRelease",
    "Staged",
    "certificate_kind",
    "site",
    "stage",
    "wait_for_https",
]

CADDY_REPO = "caddyserver/caddy"
CADDY_FLOOR = (2, 10, 0)
HTTPS_WAIT_SECONDS = 120
SOCKET = Path("/run/gitmortem/http.sock")
UPSTREAM = f"unix/{SOCKET}"
INTERNAL_ROOT = Path("/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt")
TLS_DIR = Path("/etc/caddy/tls")
TLS_CERT = TLS_DIR / "cert.pem"
TLS_KEY = TLS_DIR / "key.pem"
MAX_CADDY_BYTES = 256 << 20
_ARCHES = {"x86_64": "amd64", "arm64": "arm64"}
_PRIVATE_SUFFIXES = (".lan", ".local", ".internal", ".home.arpa", ".localdomain")

type Kind = Literal["public", "shortlived", "internal", "own"]


def certificate_kind(address: str, *, internal_tls: bool, own_cert: bool = False) -> Kind:
    if own_cert:
        return "own"
    if internal_tls:
        return "internal"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        name = address.lower().rstrip(".")
        if "." not in name or name.endswith(_PRIVATE_SUFFIXES):
            return "internal"
        return "public"
    return "shortlived" if ip.is_global else "internal"


REQUEST_BODY_CAP = "2MiB"
BARE_REPLY_HEADERS = (
    ("Content-Security-Policy", "\"default-src 'none'; frame-ancestors 'none'\""),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Strict-Transport-Security", '"max-age=31536000"'),
    ("Cache-Control", "no-store"),
)


def site(address: str, *, internal_tls: bool, own_cert: bool = False) -> str:
    kind = certificate_kind(address, internal_tls=internal_tls, own_cert=own_cert)
    lines = [f"{address} {{"]
    if kind == "own":
        lines.append(f"\ttls {TLS_CERT} {TLS_KEY}")
    elif kind == "internal":
        lines.append("\ttls internal")
    elif kind == "shortlived":
        lines += ["\ttls {", "\t\tissuer acme {", "\t\t\tprofile shortlived", "\t\t}", "\t}"]
    lines += ["\theader {", *(f"\t\t?{name} {value}" for name, value in BARE_REPLY_HEADERS), "\t}"]
    lines += ["\trequest_body {", f"\t\tmax_size {REQUEST_BODY_CAP}", "\t}"]
    lines += [
        f"\treverse_proxy {UPSTREAM} {{",
        f"\t\trequest_buffers {REQUEST_BODY_CAP}",
        "\t}",
        "}",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Staged:
    version: str
    new: Path
    sha512: str


def stage(
    github: GitHub, arch: str, staging: Path, *, have_sha512: str | None = None
) -> Staged | None:
    if arch not in _ARCHES:
        raise Mismatch(f"no Caddy build is installed for {arch}")
    release = pick(
        github.releases(CADDY_REPO), choice="latest", floor=CADDY_FLOOR, tested=(2, 0, 0)
    )
    version = ".".join(str(part) for part in release.version or (0, 0, 0))
    name = f"caddy_{version}_linux_{_ARCHES[arch]}.tar.gz"
    sums_name = f"caddy_{version}_checksums.txt"
    archive_asset, sums_asset = release.assets.get(name), release.assets.get(sums_name)
    if archive_asset is None or sums_asset is None:
        raise Mismatch(
            f"Caddy {version}: the release has no {name if archive_asset is None else sums_name}"
        )
    staging.mkdir(parents=True, exist_ok=True)
    sums_path = staging / sums_name
    github.download_asset(sums_asset, sums_path, max_bytes=1 << 20)
    if sums_asset.digest != "sha256:" + file_digest(sums_path, "sha256"):
        raise Mismatch(f"{sums_name}: it does not match GitHub's digest")
    sums = sums_path.read_bytes()
    listed = sums_line(sums, name, "sha512")
    if have_sha512 == listed:
        return None
    archive = staging / name
    github.download_asset(archive_asset, archive, max_bytes=MAX_CADDY_BYTES)
    check(archive, asset=archive_asset, sums=sums, algorithm="sha512", record=None)
    new = staging / "new-caddy"
    unpack.member(archive, "caddy", new, kind="tar.gz", max_bytes=MAX_CADDY_BYTES)
    return Staged(version, new, listed)


def wait_for_https(
    address: str,
    *,
    seconds: int = HTTPS_WAIT_SECONDS,
    port: int = 443,
    cafile: Path | None = None,
) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        try:
            context = tls_context(cafile)
            with (
                socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
                context.wrap_socket(raw, server_hostname=address) as tls,
            ):
                tls.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n".encode()
                )
                if tls.recv(16).startswith(b"HTTP/"):
                    return True
        except (OSError, ssl.SSLError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
