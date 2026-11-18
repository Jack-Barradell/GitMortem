import ipaddress
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from gitmortem import paths
from gitmortem.db.models import ToolName

_PACKAGE_STATIC = Path(__file__).parent / "static"
_RUN_BY_GIT = frozenset({ToolName.GIT_SECRETS})
BUILT_IN_TOOLS = frozenset({ToolName.CUSTOM_RULES})


class ConfigError(Exception):
    pass


class Mode(StrEnum):
    LOCAL = "local"
    SERVER = "server"


SOCKET_PEER = "localhost"


@dataclass(frozen=True)
class Settings:
    mode: Mode
    host: str
    port: int
    data_dir: Path
    key_file: Path | None
    allowed_hosts: tuple[str, ...]
    secure_cookies: bool
    trusted_proxy: str | None
    static_dir: Path = _PACKAGE_STATIC
    scan_root_bases: tuple[Path, ...] = ()
    tool_paths: Mapping[ToolName, Path] = field(default_factory=dict)
    tools_dir: Path | None = None
    unix_socket: Path | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"port {self.port} is outside 1-65535")
        if self.mode is Mode.LOCAL and not _is_loopback(self.host):
            raise ConfigError(f"local mode binds loopback only, not {self.host!r}")
        object.__setattr__(
            self, "scan_root_bases", tuple(_resolve_base(b) for b in self.scan_root_bases)
        )
        object.__setattr__(
            self, "tools_dir", (self.tools_dir or self.data_dir / "tools").absolute()
        )
        object.__setattr__(
            self,
            "tool_paths",
            MappingProxyType({tool: _tool_file(tool, p) for tool, p in self.tool_paths.items()}),
        )

    @property
    def database_path(self) -> Path:
        return self.data_dir / "gitmortem.sqlite3"

    @property
    def proxy_peer(self) -> str | None:
        return SOCKET_PEER if self.unix_socket is not None else self.trusted_proxy

    @classmethod
    def local(
        cls,
        *,
        port: int = 8765,
        data_dir: Path | None = None,
        key_file: Path | None = None,
        static_dir: Path | None = None,
        scan_root_bases: Sequence[Path] = (),
        tool_paths: Mapping[ToolName, Path] | None = None,
        tools_dir: Path | None = None,
    ) -> "Settings":
        return cls(
            mode=Mode.LOCAL,
            host="127.0.0.1",
            port=port,
            data_dir=data_dir or paths.default_data_dir(),
            key_file=key_file,
            allowed_hosts=("127.0.0.1",),
            secure_cookies=False,
            trusted_proxy=None,
            static_dir=static_dir or _PACKAGE_STATIC,
            scan_root_bases=tuple(scan_root_bases) or _home_base(),
            tool_paths=tool_paths or {},
            tools_dir=tools_dir,
        )

    @classmethod
    def server(
        cls,
        *,
        host: str,
        port: int,
        data_dir: Path,
        key_file: Path | None,
        allowed_hosts: Sequence[str],
        secure_cookies: bool = True,
        trusted_proxy: str | None = None,
        static_dir: Path | None = None,
        scan_root_bases: Sequence[Path] = (),
        tool_paths: Mapping[ToolName, Path] | None = None,
        tools_dir: Path | None = None,
        unix_socket: Path | None = None,
    ) -> "Settings":
        if not allowed_hosts:
            raise ConfigError("server mode needs at least one allowed host")
        if unix_socket is not None and trusted_proxy is not None:
            raise ConfigError(
                "--trusted-proxy is for a TCP listener: on a Unix socket the proxy is whoever "
                "may connect to it"
            )
        if unix_socket is not None and not unix_socket.is_absolute():
            raise ConfigError(f"the Unix socket {str(unix_socket)!r} must be an absolute path")
        return cls(
            mode=Mode.SERVER,
            host=host,
            port=port,
            data_dir=data_dir,
            key_file=key_file,
            allowed_hosts=tuple(normalize_allowed_host(h) for h in allowed_hosts),
            secure_cookies=secure_cookies,
            trusted_proxy=None if trusted_proxy is None else normalize_trusted_proxy(trusted_proxy),
            static_dir=static_dir or _PACKAGE_STATIC,
            scan_root_bases=tuple(scan_root_bases),
            tool_paths=tool_paths or {},
            tools_dir=tools_dir,
            unix_socket=unix_socket,
        )


def _home_base() -> tuple[Path, ...]:
    try:
        home = Path.home()
    except RuntimeError:
        return ()
    return (home,) if home.is_dir() else ()


def _resolve_base(raw: Path) -> Path:
    try:
        resolved: Path | None = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        resolved = None
    if resolved is None or not resolved.is_dir():
        raise ConfigError(f"scan root base {str(raw)!r} must be an existing directory")
    return resolved


def tool_file_names(tool: ToolName, *, windows: bool) -> tuple[str, ...]:
    if windows and tool not in _RUN_BY_GIT:
        return (f"{tool.value}.exe",)
    return (tool.value,)


def _tool_file(tool: ToolName, raw: Path, *, windows: bool = os.name == "nt") -> Path:
    if tool in BUILT_IN_TOOLS:
        raise ConfigError(_built_in(tool))
    absolute = Path(os.path.abspath(raw))
    if not absolute.is_file():
        raise ConfigError(f"the path for {tool.value} ({str(raw)!r}) must be an existing file")
    names = tool_file_names(tool, windows=windows)
    if absolute.name not in names:
        why = ": git runs it by that name" if tool in _RUN_BY_GIT else ""
        raise ConfigError(
            f"the path for {tool.value} ({str(raw)!r}) must be a file named {names[0]}{why}"
        )
    return absolute


def _built_in(tool: ToolName) -> str:
    return f"--tool-path cannot name {tool.value}: {tool.value} is built into GitMortem"


def parse_tool_paths(pairs: Sequence[str]) -> dict[ToolName, Path]:
    parsed: dict[ToolName, Path] = {}
    for pair in pairs:
        name, _, raw = pair.partition("=")
        if not name or not raw:
            raise ConfigError(f"--tool-path {pair!r} must look like NAME=PATH")
        try:
            tool = ToolName(name)
        except ValueError:
            known = ", ".join(t.value for t in ToolName if t not in BUILT_IN_TOOLS)
            raise ConfigError(
                f"--tool-path names an unknown tool {name!r} (known: {known})"
            ) from None
        if tool in BUILT_IN_TOOLS:
            raise ConfigError(_built_in(tool))
        if tool in parsed:
            raise ConfigError(f"--tool-path names {tool.value} more than once")
        parsed[tool] = Path(raw)
    return parsed


def normalize_allowed_host(raw: str) -> str:
    host = raw.strip().lower()
    if not host or any(c in host for c in ":/[]\\@?#") or any(c.isspace() for c in host):
        raise ConfigError(
            f"allowed host {raw!r} must be a bare host name or IPv4 address "
            "(no scheme, port, path or brackets)"
        )
    if host.startswith("."):
        raise ConfigError(
            f"allowed host {raw!r} must not start with '.': list each name exactly "
            "(a leading dot would trust every subdomain)"
        )
    return host


def normalize_trusted_proxy(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        raise ConfigError(
            f"trusted proxy {raw!r} must be the proxy's IP address, as the server sees it "
            "connect (e.g. 127.0.0.1)"
        ) from None


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def guarded_key_file(settings: Settings) -> Path | None:
    if settings.key_file is None and settings.mode is Mode.LOCAL:
        return paths.default_key_file()
    return settings.key_file
