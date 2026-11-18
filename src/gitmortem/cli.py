import contextlib
import errno
import getpass
import logging
import os
import platform
import signal
import socket
import sqlite3
import sys
import threading
import webbrowser
from collections.abc import Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn, cast
from wsgiref.types import StartResponse, WSGIApplication, WSGIEnvironment

import click
import waitress.server
from apiflask import APIFlask
from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker
from waitress.adjustments import Adjustments
from waitress.channel import HTTPChannel
from waitress.server import BaseWSGIServer, MultiSocketServer

from gitmortem import console, instance_lock, paths, privacy
from gitmortem.accounts import audit, users
from gitmortem.accounts.audit import AuditAction
from gitmortem.accounts.refusals import RefusalFlusher, RefusalTally
from gitmortem.config import SOCKET_PEER, ConfigError, Settings, parse_tool_paths
from gitmortem.corpus import DEFAULT_SEED, CorpusError, generate, preflight
from gitmortem.corpus.fakes import Role as SecretRole
from gitmortem.corpus.manifest import RepoKind, Size
from gitmortem.db import (
    UnsupportedSQLite,
    make_engine,
    make_session_factory,
    require_supported_sqlite,
    schema_is_behind,
    truncate_journal,
    upgrade_database,
    write_engine,
)
from gitmortem.db.compact import CompactRefused, check_temp_folder, compact
from gitmortem.db.keycheck import KeyMismatch, check_instance_key, remember_key_check
from gitmortem.db.models import AuditValue, Role, ToolName, User
from gitmortem.gitrun import GitError, GitRunner, GitUnavailable, git_runner
from gitmortem.keys import (
    ENV_VAR,
    InstanceKeyError,
    KeyPurpose,
    derive_subkey,
    read_existing_key,
    resolve_instance_key,
)
from gitmortem.paths import default_data_dir
from gitmortem.scanning.jobs import WORK
from gitmortem.scanning.registry import DetectionFolderError
from gitmortem.scanning.service import SHUTDOWN_SECONDS, ScanService
from gitmortem.scanning.tools import Detection, DetectionStatus, detection_changes
from gitmortem.scanning.uow import unit_of_work
from gitmortem.web.app import MAX_BODY_BYTES, create_app

BROWSER_DELAY_SECONDS = 0.5
MAX_AUDIT_AGE_DAYS = 36_500
THREADS = 8
SOCKET_PERMS = "660"
DEFAULT_SERVER_PORT = 8080
RECV_BYTES = 8192
RESPONSE_PIECE_BYTES = 32 << 10
OUTBUF_HIGH_WATERMARK = 1 << 20
OUTBUF_OVERFLOW = OUTBUF_HIGH_WATERMARK + 2 * RESPONSE_PIECE_BYTES
MAX_RESPONSE_HEADER_BYTES = 16 << 10
STALLED_REPLY_CUT_SECONDS = (
    Adjustments.channel_timeout,
    Adjustments.channel_timeout + Adjustments.cleanup_interval,
)
REQUEST_SECONDS = 60
STALLED_REQUEST_CUT_SECONDS = (
    REQUEST_SECONDS,
    REQUEST_SECONDS + 2 * Adjustments.cleanup_interval,
)
CONNECTION_LIMIT = 1000
STUCK_EXIT = 3
PORT = click.IntRange(1, 65535)
SCAN_ROOT_BASE = click.option(
    "--scan-root-base",
    "scan_root_bases",
    multiple=True,
    type=click.Path(path_type=Path),
    help="A folder scan roots may be added inside. Repeatable. Local mode defaults to your "
    "home folder; server mode has none until you name one.",
)
TOOL_PATH = click.option(
    "--tool-path",
    "tool_paths",
    multiple=True,
    metavar="NAME=PATH",
    help="Where a scanner tool is, e.g. git-secrets=/usr/local/bin/git-secrets. Repeatable. "
    "A tool not named here is looked up in the tools folder, then on PATH.",
)
TOOLS_DIR = click.option(
    "--tools-dir",
    type=click.Path(path_type=Path),
    help="The folder install-scanners puts the scanners in, looked in before PATH. "
    "Defaults to <data dir>/tools.",
)


class StartupError(Exception):
    pass


class ResponseHeadersTooLarge(RuntimeError):
    def __init__(self) -> None:
        super().__init__(f"a reply's headers are over {MAX_RESPONSE_HEADER_BYTES} bytes")


class _Pieces:
    def __init__(self, body: Iterable[bytes]) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._body:
            for at in range(0, len(chunk), RESPONSE_PIECE_BYTES):
                yield chunk[at : at + RESPONSE_PIECE_BYTES]

    def close(self) -> None:
        close = getattr(self._body, "close", None)
        if close is not None:
            close()


class BoundedResponses:
    def __init__(self, app: WSGIApplication) -> None:
        self.app = app

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        def start(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            size = len(status) + sum(len(name) + len(value) + 4 for name, value in headers)
            if size > MAX_RESPONSE_HEADER_BYTES:
                raise ResponseHeadersTooLarge
            write = start_response(status, headers, exc_info)

            def write_pieces(data: bytes) -> None:
                for piece in _Pieces([data]):
                    write(piece)

            return write_pieces

        body = self.app(environ, start)
        file_wrapper = environ.get("wsgi.file_wrapper")
        if isinstance(file_wrapper, type) and isinstance(body, file_wrapper):
            return body
        return _Pieces(body)


def _die(message: str) -> NoReturn:
    console.error(message)
    raise SystemExit(1)


@contextmanager
def _clean_errors() -> Iterator[None]:
    try:
        yield
    except (ConfigError, InstanceKeyError, StartupError, UnsupportedSQLite) as exc:
        _die(str(exc))


def _engine(data_dir: Path) -> Engine:
    try:
        return make_engine(data_dir / "gitmortem.sqlite3")
    except OSError as exc:
        raise StartupError(f"cannot use data directory {data_dir}: {exc}") from exc


def _upgrade(engine: Engine, instance_key: bytes | None = None) -> None:
    try:
        upgrade_database(engine, instance_key=instance_key)
    except Exception as exc:
        engine.dispose()
        raise StartupError(f"The database could not be upgraded: {exc}") from exc


def _open_database(data_dir: Path, instance_key: bytes | None = None) -> Engine:
    engine = _engine(data_dir)
    _upgrade(engine, instance_key)
    return engine


def _open_database_beside_a_server(data_dir: Path) -> Engine:
    engine = _engine(data_dir)
    try:
        behind = schema_is_behind(engine)
    except Exception as exc:
        engine.dispose()
        raise StartupError(f"The database could not be upgraded: {exc}") from exc
    if behind:
        try:
            with instance_lock.hold(data_dir):
                _upgrade(engine)
        except instance_lock.InstanceLocked:
            engine.dispose()
            raise StartupError(f"stop the running GitMortem before upgrading {data_dir}") from None
        except OSError as exc:
            engine.dispose()
            raise StartupError(f"cannot use data directory {data_dir}: {exc}") from exc
    return engine


def _make_data_dir(settings: Settings) -> None:
    _make_data_folder(settings.data_dir)


def _make_data_folder(data_dir: Path) -> None:
    try:
        made = not data_dir.exists()
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if made:
            privacy.make_owner_only(data_dir)
        _require_own_folder(data_dir)
    except OSError as exc:
        raise StartupError(f"cannot use data directory {data_dir}: {exc}") from exc


def _require_own_folder(data_dir: Path) -> None:
    hint = "name a folder of your own with --data-dir"
    if sys.platform != "win32" and os.name == "posix":
        held = data_dir.stat()
        if held.st_uid != os.geteuid():
            raise StartupError(f"data directory {data_dir} is owned by another user; {hint}")
        if held.st_mode & 0o022:
            raise StartupError(
                f"data directory {data_dir} is writable by others than its owner: run"
                f" chmod go-w {data_dir}, or {hint}"
            )
    try:
        privacy.require_private(data_dir, "data directory", reading=False, hint=hint)
    except privacy.NotPrivate as exc:
        raise StartupError(str(exc)) from None


def _hold_instance_lock(stack: ExitStack, data_dir: Path) -> None:
    try:
        stack.enter_context(instance_lock.hold(data_dir))
    except instance_lock.InstanceLocked as exc:
        raise StartupError(str(exc)) from None
    except OSError as exc:
        raise StartupError(f"cannot use data directory {data_dir}: {exc}") from exc


def prepare(settings: Settings) -> tuple[Engine, bytes]:
    key, created = resolve_instance_key(settings, os.environ)
    engine = _engine(settings.data_dir)
    try:
        check_instance_key(engine, key, created=created is not None)
    except KeyMismatch as exc:
        engine.dispose()
        if created is not None:
            created.unlink(missing_ok=True)
        raise StartupError(str(exc)) from None
    _upgrade(engine, key)
    remember_key_check(engine, key)
    if created is not None:
        console.info(
            f"Created instance key at {created}. Back it up: the secret material GitMortem "
            "stores cannot be read without it."
        )
    return engine, key


def stdin_is_a_terminal() -> bool:
    if sys.stdin is None:
        return False
    try:
        return sys.stdin.isatty()
    except ValueError:
        return False


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        if stdin_is_a_terminal():
            return getpass.getpass("Password: ")
        line = sys.stdin.readline()
        return line.removesuffix("\n").removesuffix("\r")
    return str(click.prompt("Password", hide_input=True, confirmation_prompt=True))


def _create_admin(
    factory: sessionmaker[Session], *, username: str, password: str, pepper: bytes | None = None
) -> User:
    with factory() as session:
        try:
            if users.count_active_admins(session) == 0:
                user = users.bootstrap_admin(
                    session, username=username, password=password, pepper=pepper
                )
            else:
                user = users.create_user(
                    session,
                    username=username,
                    password=password,
                    role=Role.ADMIN,
                    actor=None,
                    ip=None,
                    must_change=False,
                    pepper=pepper,
                )
            session.commit()
        except users.UserError:
            session.rollback()
            raise
        return user


def ensure_admin(
    factory: sessionmaker[Session],
    *,
    interactive: bool,
    data_dir: Path | None = None,
    pepper: bytes | None = None,
) -> None:
    with factory() as session:
        has_admin = users.count_active_admins(session) > 0
    if has_admin:
        return
    if not interactive:
        _die(
            "No admin account exists. Create one with: gitmortem create-admin "
            f"--data-dir {data_dir or default_data_dir()} --username <name>"
        )
    console.info("No admin account exists yet. Create the first one.")
    while True:
        username = str(click.prompt("Admin username"))
        password = _read_password(False)
        try:
            user = _create_admin(factory, username=username, password=password, pepper=pepper)
        except users.UserError as exc:
            console.error(str(exc))
            continue
        console.ok(f"Created admin {user.username}.")
        return


def _ensure_port_free(host: str, port: int) -> None:
    try:
        family, kind, proto, _name, address = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
        )[0]
    except socket.gaierror as exc:
        _die(f"Cannot use host {host!r}: {exc.strerror or exc}")
    with socket.socket(family, kind, proto) as probe:
        if os.name == "posix":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(address)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                _die(f"Port {port} is already in use. Choose another with --port.")
            _die(f"Cannot listen on {host}:{port}: {exc.strerror or exc}")


class _CloseStalledReplies:
    def __init__(self, server: BaseWSGIServer) -> None:
        self._server = server
        self._own = cast("Any", server.maintenance)
        self._arriving: dict[int, float] = {}

    def __call__(self, now: float) -> None:
        self._own(now)
        cutoff = now - self._server.adj.channel_timeout
        channels = cast("dict[int, HTTPChannel]", self._server.active_channels)
        arriving: dict[int, float] = {}
        for channel in list(channels.values()):
            stalled = channel.socket
            if stalled is None:
                continue
            reply_stalled = (
                channel.requests and channel.total_outbufs_len and channel.last_activity < cutoff
            )
            partial = channel.request is not None and not channel.request.completed
            if partial:
                arriving[id(channel)] = self._arriving.get(id(channel), now)
            if reply_stalled or (partial and now - arriving[id(channel)] >= REQUEST_SECONDS):
                with contextlib.suppress(OSError):
                    stalled.shutdown(socket.SHUT_RDWR)
        self._arriving = arriving


def exclusive_listener(host: str, port: int) -> socket.socket:
    if sys.platform != "win32":
        raise OSError("an exclusive listener is made only on Windows")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((host, port))
    except BaseException:
        listener.close()
        raise
    return listener


def build_server(app: WSGIApplication, **options: Any) -> MultiSocketServer | BaseWSGIServer:
    if sys.platform == "win32" and "host" in options and "sockets" not in options:
        host, port = options.pop("host"), options.pop("port")
        options["sockets"] = [exclusive_listener(host, port)]
    server = waitress.server.create_server(BoundedResponses(app), **options)
    if isinstance(server, BaseWSGIServer):
        listening = [server]
    else:
        held: Iterable[object] = (server.map or {}).values()
        listening = [each for each in held if isinstance(each, BaseWSGIServer)]
    for each in listening:
        each.maintenance = _CloseStalledReplies(each)  # type: ignore[method-assign]
    return server


def waitress_options(
    host: str, port: int, trusted_proxy: str | None, *, unix_socket: Path | None = None
) -> dict[str, Any]:
    where: dict[str, Any] = (
        {"host": host, "port": port}
        if unix_socket is None
        else {"unix_socket": str(unix_socket), "unix_socket_perms": SOCKET_PERMS}
    )
    if unix_socket is not None:
        trusted_proxy = SOCKET_PEER
    options: dict[str, Any] = {
        **where,
        "threads": THREADS,
        "max_request_body_size": MAX_BODY_BYTES + 1,
        "recv_bytes": RECV_BYTES,
        "inbuf_overflow": MAX_BODY_BYTES + 1 + RECV_BYTES,
        "outbuf_high_watermark": OUTBUF_HIGH_WATERMARK,
        "outbuf_overflow": OUTBUF_OVERFLOW,
        "clear_untrusted_proxy_headers": True,
        "connection_limit": CONNECTION_LIMIT,
        "asyncore_use_poll": True,
    }
    if trusted_proxy is not None:
        options |= {
            "trusted_proxy": trusted_proxy,
            "trusted_proxy_count": 1,
            "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto"},
        }
    return options


def serve_app(
    app: APIFlask,
    *,
    host: str,
    port: int,
    browser_url: str | None,
    trusted_proxy: str | None = None,
    unix_socket: Path | None = None,
) -> None:
    if unix_socket is None:
        _ensure_port_free(host, port)
    timer: threading.Timer | None = None
    if browser_url is not None:
        timer = threading.Timer(BROWSER_DELAY_SECONDS, webbrowser.open, [browser_url])
        timer.daemon = True
        timer.start()
    where = f"http://{host}:{port}/" if unix_socket is None else f"the Unix socket {unix_socket}"
    console.info(f"GitMortem is running at {where} (Ctrl+C to stop)")
    logging.basicConfig()
    try:
        try:
            server = build_server(
                app, **waitress_options(host, port, trusted_proxy, unix_socket=unix_socket)
            )
        except OSError:
            if unix_socket is not None:
                _die(f"Cannot listen on the Unix socket {unix_socket}.")
            _die(f"Port {port} is already in use. Choose another with --port.")
        server.run()
    finally:
        if timer is not None:
            timer.cancel()


def _report_detection(name: str, detection: Detection) -> None:
    where = f" at {detection.path}" if detection.path else ""
    match detection.status:
        case DetectionStatus.FOUND:
            console.ok(f"{detection.identity}{where}")
        case DetectionStatus.UNRECOGNISED:
            console.info(f"{name}{where} is an unrecognised build; it will run, unverified")
        case DetectionStatus.MISSING:
            console.fail(f"{name} was not found; scans with it are unavailable")
        case DetectionStatus.NOT_EXECUTABLE:
            console.error(f"{name}{where} cannot be run (not executable or not readable)")
        case DetectionStatus.SHADOWED:
            console.error(
                f"{name}{where} is shadowed by another {name} in git's exec-path; "
                "scans with it are refused"
            )
        case DetectionStatus.UNSAFE_FOLDER:
            console.error(
                f"{name}{where} is in a tools folder another user owns or others can write; "
                "scans with it are refused"
            )
        case DetectionStatus.UNTESTED:
            console.info(
                f"{detection.identity}{where} is a version GitMortem has not tested; "
                "it will run, unverified"
            )
        case DetectionStatus.UNSUPPORTED if detection.identity:
            console.error(
                f"{detection.identity}{where} is older than GitMortem supports; "
                "scans with it are refused"
            )
        case DetectionStatus.UNSUPPORTED:
            console.error(
                f"{name}{where} reported no version GitMortem can read; scans with it are refused"
            )


def _stopping_signals() -> tuple[signal.Signals, ...]:
    if sys.platform == "win32":
        return (signal.SIGTERM,)
    return (signal.SIGTERM, signal.SIGHUP)


def _ignore_stopping_signals() -> None:
    for each in _stopping_signals():
        signal.signal(each, signal.SIG_IGN)


@contextmanager
def _sigterm_exits() -> Iterator[None]:
    def stop(_signum: int, _frame: FrameType | None) -> None:
        _ignore_stopping_signals()
        raise SystemExit(0)

    previous = {each: signal.signal(each, stop) for each in _stopping_signals()}
    try:
        yield
    finally:
        for each, handler in previous.items():
            signal.signal(each, handler)


def _audit_start(
    engine: Engine, settings: Settings, detections: Mapping[ToolName, Detection]
) -> None:
    started: dict[str, AuditValue] = {
        "mode": settings.mode.value,
        "host": settings.host,
        "port": settings.port,
        "unix_socket": None if settings.unix_socket is None else str(settings.unix_socket),
        "bases": [str(base) for base in settings.scan_root_bases],
        "tool_paths": {name.value: str(path) for name, path in settings.tool_paths.items()},
    }
    with unit_of_work(engine) as session:
        audit.record(session, AuditAction.INSTANCE_STARTED, actor=None, detail=started)
        audit.record(
            session,
            AuditAction.TOOLS_DETECTED,
            actor=None,
            detail={"via": "start", "changed": detection_changes({}, detections)},
        )


def _end_holding_the_lock() -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(STUCK_EXIT)


def _serve_with_scans(
    settings: Settings, engine: Engine, key: bytes, runner: GitRunner, browser_url: str | None
) -> None:
    scans = ScanService(engine, key, settings, runner=runner)
    try:
        scans.recover()
    except OSError as exc:
        raise StartupError(
            f"cannot clear {settings.data_dir / WORK}: {exc.strerror or exc}"
        ) from exc
    try:
        detections = scans.detect()
    except (GitUnavailable, GitError) as exc:
        raise StartupError(str(exc)) from exc
    except DetectionFolderError as exc:
        raise StartupError(
            f"cannot make detection's folder in {exc.filename}: {exc.strerror or exc}"
        ) from exc
    except OSError as exc:
        raise StartupError(f"cannot detect the tools: {exc.strerror or exc}") from exc
    for name, detection in detections.items():
        _report_detection(name.value, detection)
    _audit_start(engine, settings, detections)
    tally = RefusalTally()
    flusher = RefusalFlusher(
        tally,
        engine,
        report=lambda exc: console.error(f"refusals were not audited ({type(exc).__name__})"),
    )
    with _sigterm_exits():
        try:
            scans.start()
            app = create_app(settings, instance_key=key, engine=engine, scans=scans, refusals=tally)
            flusher.start()
            serve_app(
                app,
                host=settings.host,
                port=settings.port,
                browser_url=browser_url,
                trusted_proxy=settings.trusted_proxy,
                unix_socket=settings.unix_socket,
            )
        finally:
            _ignore_stopping_signals()
            flusher.stop()
            if not scans.shutdown():
                console.error(
                    f"some scan jobs had not stopped after {SHUTDOWN_SECONDS:g} s; their runs "
                    "are marked interrupted, and GitMortem stops with them, holding its lock "
                    "to the end"
                )
                _end_holding_the_lock()


def _run(settings: Settings, *, browser_url: str | None) -> None:
    if settings.unix_socket is None:
        _ensure_port_free(settings.host, settings.port)
    require_supported_sqlite()
    _make_data_dir(settings)
    with ExitStack() as stack:
        _hold_instance_lock(stack, settings.data_dir)
        engine, key = prepare(settings)
        try:
            ensure_admin(
                make_session_factory(write_engine(engine)),
                interactive=stdin_is_a_terminal(),
                data_dir=settings.data_dir,
                pepper=derive_subkey(key, KeyPurpose.PASSWORD),
            )
            with git_runner() as runner:
                _serve_with_scans(settings, engine, key, runner, browser_url)
        finally:
            engine.dispose()


@click.group(help="GitMortem: secret-exposure triage.")
def main() -> None:
    pass


@main.command(help="Run for one person on this machine, bound to 127.0.0.1 only.")
@click.option("--port", default=8765, show_default=True, type=PORT, help="Port on 127.0.0.1.")
@click.option("--data-dir", type=click.Path(path_type=Path), help="Where the database lives.")
@click.option("--key-file", type=click.Path(path_type=Path), help="Instance key file.")
@click.option("--no-browser", is_flag=True, help="Do not open the browser.")
@SCAN_ROOT_BASE
@TOOL_PATH
@TOOLS_DIR
def local(
    port: int,
    data_dir: Path | None,
    key_file: Path | None,
    no_browser: bool,
    scan_root_bases: tuple[Path, ...],
    tool_paths: tuple[str, ...],
    tools_dir: Path | None,
) -> None:
    with _clean_errors():
        settings = Settings.local(
            port=port,
            data_dir=data_dir,
            key_file=key_file,
            scan_root_bases=scan_root_bases,
            tool_paths=parse_tool_paths(tool_paths),
            tools_dir=tools_dir,
        )
        url = None if no_browser else f"http://127.0.0.1:{port}/"
        _run(settings, browser_url=url)


@main.command(help="Run as a team server on a configured interface or a Unix socket.")
@click.option("--host", help="Interface to bind, e.g. 0.0.0.0.")
@click.option("--port", type=PORT, help="Port on that interface.  [default: 8080]")
@click.option(
    "--unix-socket",
    type=click.Path(path_type=Path),
    help="Listen on this Unix socket instead of a TCP port (POSIX); the proxy that connects to "
    "it is the one whose forwarding headers are believed.",
)
@click.option("--data-dir", required=True, type=click.Path(path_type=Path))
@click.option(
    "--allowed-host",
    "allowed_hosts",
    required=True,
    multiple=True,
    help="A Host name clients use (bare name or IPv4; no scheme, port or path). Repeatable.",
)
@click.option(
    "--key-file", type=click.Path(path_type=Path), help=f"Instance key file, if {ENV_VAR} is unset."
)
@click.option(
    "--trusted-proxy",
    metavar="ADDRESS",
    help="The reverse proxy's IP address; X-Forwarded-For/-Proto are believed only from it.",
)
@click.option("--insecure-cookies", is_flag=True, help="Drop the Secure flag (plain HTTP only).")
@SCAN_ROOT_BASE
@TOOL_PATH
@TOOLS_DIR
def serve(
    host: str | None,
    port: int | None,
    unix_socket: Path | None,
    data_dir: Path,
    allowed_hosts: tuple[str, ...],
    key_file: Path | None,
    trusted_proxy: str | None,
    insecure_cookies: bool,
    scan_root_bases: tuple[Path, ...],
    tool_paths: tuple[str, ...],
    tools_dir: Path | None,
) -> None:
    if unix_socket is not None:
        if sys.platform == "win32":
            raise click.UsageError("--unix-socket is for POSIX systems")
        if host is not None or port is not None:
            raise click.UsageError("give --unix-socket or --host and --port, not both")
    elif host is None:
        raise click.UsageError("give --host (or --unix-socket)")
    with _clean_errors():
        settings = Settings.server(
            host=host or "localhost",
            port=port or DEFAULT_SERVER_PORT,
            unix_socket=unix_socket,
            data_dir=data_dir,
            key_file=key_file,
            allowed_hosts=allowed_hosts,
            secure_cookies=not insecure_cookies,
            trusted_proxy=trusted_proxy,
            scan_root_bases=scan_root_bases,
            tool_paths=parse_tool_paths(tool_paths),
            tools_dir=tools_dir,
        )
        if insecure_cookies:
            console.error(
                "--insecure-cookies: session cookies are sent without the Secure flag. "
                "Use it only on a network you trust."
            )
        elif trusted_proxy is None and unix_socket is None:
            console.info(
                "Session cookies are Secure, so browsers keep them only over HTTPS, and this "
                "server speaks plain HTTP. Put a TLS proxy in front (and pass --trusted-proxy), "
                "or pass --insecure-cookies for plain HTTP on a network you trust."
            )
        _run(settings, browser_url=None)


def _this_machine() -> tuple[str, str]:
    return platform.system(), platform.machine()


def _newer_than_tested(tool: str, version: str) -> str | None:
    from gitmortem.scanning import gitleaks, trufflehog

    tested = {"gitleaks": gitleaks.TESTED, "trufflehog": trufflehog.TESTED}.get(tool)
    if tested is None:
        return None
    was = ".".join(str(part) for part in tested)
    if tool == "gitleaks":
        lacks = (
            f"rules added since {was} do not run, since GitMortem builds its config from {was}'s"
        )
    else:
        lacks = f"detectors added since {was} run, but cannot be switched off on the Tools page"
    return (
        f"{tool} {version} is newer than the {was} GitMortem was tested with: it runs with an "
        f"untested warning, and {lacks}"
    )


@main.command(
    "install-scanners",
    help="Download and check the scanners into the tools folder. This command goes online.",
)
@click.option(
    "--choice",
    type=click.Choice(["known-good", "latest"]),
    required=True,
    help="known-good: the versions this GitMortem was tested with. latest: each tool's newest "
    "compatible release at least 7 days old.",
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Where the database lives.")
@TOOLS_DIR
@click.option("--if-missing", is_flag=True, help="Do nothing when every scanner is there.")
def install_scanners(
    choice: str, data_dir: Path | None, tools_dir: Path | None, if_missing: bool
) -> None:
    from gitmortem.install import github, scanners
    from gitmortem.install.select import NoRelease
    from gitmortem.install.unpack import UnpackRefused
    from gitmortem.install.verify import Mismatch

    data = (data_dir or default_data_dir()).absolute()
    target = (tools_dir or data / "tools").absolute()
    if tools_dir is None:
        try:
            _make_data_folder(data)
        except StartupError as exc:
            _die(f"{exc}; no scanner was changed")
    try:
        machine = scanners.platform_of(*_this_machine())
        done = scanners.install(
            target,
            "latest" if choice == "latest" else "known-good",
            github=github.GitHub(api=github.API, raw=github.RAW),
            platform=machine,
            if_missing=if_missing,
        )
    except (
        scanners.UnsupportedPlatform,
        scanners.UnsafeFolder,
        github.GitHubError,
        Mismatch,
        NoRelease,
        UnpackRefused,
        OSError,
    ) as exc:
        _die(f"{exc}; no scanner was changed")
    except scanners.PartlyChanged as exc:
        _die(f"{exc}: run install-scanners again")
    if not done:
        console.info("every scanner is already installed")
        return
    for item in done:
        console.ok(f"{item.tool} {item.version} ({item.choice})")
        said = _newer_than_tested(item.tool, item.version) if item.newer_than_tested else None
        if said:
            console.info(said)
        for tag in item.not_installed:
            console.info(
                f"git-secrets {tag} is newer, but publishes no checksums GitMortem could check, "
                f"so {item.version} was installed"
            )
    console.info(f"Scanners are in {target / 'bin'}")


@main.command(
    "setup-server",
    help=(
        "Set GitMortem up as a service on this Ubuntu server, behind Caddy with HTTPS. Run it as"
        " root through install.sh --server. This command goes online."
    ),
)
@click.option("--address", help="The server's domain name or IPv4 address.")
@click.option(
    "--choice",
    type=click.Choice(["known-good", "latest"]),
    help="The scanners: known-good or latest (asked when not given).",
)
@click.option(
    "--internal-tls",
    is_flag=True,
    help="Use Caddy's own certificate authority, for a name or address no public one can check.",
)
@click.option("--admin", "admin_name", help="The first admin's username, when there is none.")
@click.option("--password-stdin", is_flag=True, help="Read that admin's password from stdin.")
@click.option(
    "--cert",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Your own certificate (PEM, with its chain) for Caddy to serve, with --key; kept when "
    "the setup runs again.",
)
@click.option(
    "--key",
    "key_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="The private key (PEM) of --cert.",
)
def setup_server(
    address: str | None,
    choice: str | None,
    internal_tls: bool,
    admin_name: str | None,
    password_stdin: bool,
    cert: Path | None,
    key_path: Path | None,
) -> None:
    if password_stdin and admin_name is None:
        raise click.UsageError("--password-stdin reads the password of --admin, so give --admin")
    if (cert is None) != (key_path is None):
        raise click.UsageError("give --cert and --key together")
    if cert is not None and internal_tls:
        raise click.UsageError("--cert and --internal-tls are two different certificates")
    if sys.platform == "win32":
        _die("setup-server sets up an Ubuntu server, so it does not run on Windows")
    from gitmortem.install import github, server
    from gitmortem.install.scanners import UnsafeFolder
    from gitmortem.install.select import NoRelease
    from gitmortem.install.unpack import UnpackRefused
    from gitmortem.install.verify import Mismatch

    system = server.RealSystem()
    if not system.is_root():
        _die("setup-server sets up system services, so run it with sudo")
    release = Path(sys.prefix)
    if release.parent != server.OPT / "releases":
        _die(
            "run setup-server through sudo ./install.sh --server, which installs under "
            f"{server.OPT}"
        )
    if address is None:
        address = str(click.prompt("The server's address (a domain name or an IPv4 address)"))
    if choice is None:
        choice = str(
            click.prompt(
                "Scanners: known-good (tested with this GitMortem) or latest (newest, 7+ days old)",
                type=click.Choice(["known-good", "latest"]),
            )
        )
    admin = server.Admin(admin_name, _read_password(password_stdin)) if admin_name else None
    plan = server.SetupPlan(
        address,
        "latest" if choice == "latest" else "known-good",
        internal_tls,
        admin,
        release,
        cert=cert,
        key=key_path,
    )
    try:
        result = server.setup(
            plan, system=system, github=github.GitHub(api=github.API, raw=github.RAW)
        )
    except (
        server.SetupRefused,
        UnsafeFolder,
        github.GitHubError,
        Mismatch,
        NoRelease,
        UnpackRefused,
        OSError,
    ) as exc:
        _die(str(exc))
    code, lines = server.report(result)
    for line in lines:
        click.echo(line)
    if code:
        raise SystemExit(code)


@main.command(
    "create-admin",
    help="Create the first admin, or a further one.",
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Where the database lives.")
@click.option("--username", required=True)
@click.option("--password-stdin", is_flag=True, help="Read the password from one line of stdin.")
def create_admin(data_dir: Path | None, username: str, password_stdin: bool) -> None:
    with _clean_errors():
        engine = _open_database_beside_a_server(data_dir or default_data_dir())
    try:
        password = _read_password(password_stdin)
        try:
            user = _create_admin(
                make_session_factory(write_engine(engine)), username=username, password=password
            )
        except users.UserError as exc:
            _die(str(exc))
        console.ok(f"Created admin {user.username}.")
    finally:
        engine.dispose()


@main.command(
    "has-admin",
    hidden=True,
    help="Exit 0 when the database has an active admin and 1 when it has none, reading it "
    "read-only and changing nothing.",
)
@click.option("--data-dir", required=True, type=click.Path(path_type=Path))
def has_admin(data_dir: Path) -> None:
    database = data_dir / "gitmortem.sqlite3"
    if not database.is_file():
        raise SystemExit(1)
    try:
        with contextlib.closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as db:
            db.execute("PRAGMA trusted_schema = OFF")
            kind = db.execute("SELECT type FROM sqlite_schema WHERE name = 'users'").fetchone()
            if kind != ("table",):
                console.error(f"{database} has no users table")
                raise SystemExit(2)
            found = db.execute(
                "SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 LIMIT 1"
            ).fetchone()
    except sqlite3.Error as exc:
        console.error(f"cannot read {database}: {exc}")
        raise SystemExit(2) from None
    raise SystemExit(0 if found is not None else 1)


@main.command(
    "reset-password",
    help="Set a new password for a user, e.g. to recover a locked-out admin.",
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Where the database lives.")
@click.option(
    "--key-file",
    type=click.Path(path_type=Path),
    help=f"Instance key file, if {ENV_VAR} is unset. Read only, never created.",
)
@click.option("--username", required=True)
@click.option("--password-stdin", is_flag=True, help="Read the password from one line of stdin.")
@click.option(
    "--clear-all-lockouts",
    is_flag=True,
    help="Clear every sign-in lockout, not only this user's.",
)
def reset_password(
    data_dir: Path | None,
    key_file: Path | None,
    username: str,
    password_stdin: bool,
    clear_all_lockouts: bool,
) -> None:
    with _clean_errors():
        engine = _open_database_beside_a_server(data_dir or default_data_dir())
    try:
        with _clean_errors():
            key = _existing_key(engine, key_file)
        password = _read_password(password_stdin)
        with make_session_factory(write_engine(engine))() as session:
            try:
                target = session.scalars(
                    select(User).where(User.username == users.normalize_username(username))
                ).one_or_none()
                if target is None:
                    raise users.UserNotFound(f"no user named {username!r}")
                users.reset_password(
                    session,
                    actor=None,
                    target=target,
                    new_password=password,
                    ip=None,
                    throttle_key=None if key is None else derive_subkey(key, KeyPurpose.THROTTLE),
                    must_change=False,
                    pepper=None if key is None else derive_subkey(key, KeyPurpose.PASSWORD),
                    clear_all_lockouts=clear_all_lockouts,
                )
                session.commit()
            except users.UserError as exc:
                session.rollback()
                _die(str(exc))
            console.ok(f"Reset the password for {target.username}. Its sessions are signed out.")
            if clear_all_lockouts:
                console.info("Every sign-in lockout was cleared.")
            elif key is None:
                console.info(
                    "No instance key was found, so no sign-in lockout was cleared: each lapses"
                    " within 15 minutes. Pass --clear-all-lockouts to clear every one now."
                )
    finally:
        engine.dispose()


def _existing_key(engine: Engine, key_file: Path | None) -> bytes | None:
    try:
        key = read_existing_key(key_file or paths.default_key_file(), os.environ)
    except InstanceKeyError as exc:
        raise StartupError(str(exc)) from None
    if key is None:
        return None
    try:
        check_instance_key(engine, key, created=False)
    except KeyMismatch as exc:
        raise StartupError(str(exc)) from None
    return key


@main.command(
    "clear-audit",
    help="Delete audit events, leaving one event that records the clear.",
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Where the database lives.")
@click.option(
    "--older-than",
    "older_than",
    type=click.IntRange(min=1, max=MAX_AUDIT_AGE_DAYS),
    metavar="DAYS",
    help="Delete the events older than this many days.",
)
@click.option("--all", "everything", is_flag=True, help="Delete every event.")
@click.option("--yes", is_flag=True, help="Delete without asking.")
@click.option(
    "--vacuum", is_flag=True, help="Then shrink the database file (stop GitMortem first)."
)
def clear_audit(
    data_dir: Path | None, older_than: int | None, everything: bool, yes: bool, vacuum: bool
) -> None:
    if (older_than is not None) == everything:
        _die("Give exactly one of --older-than DAYS and --all.")
    data_dir = data_dir or default_data_dir()
    if not (data_dir / "gitmortem.sqlite3").is_file():
        _die(f"No GitMortem database in {data_dir}.")
    with ExitStack() as stack:
        if vacuum:
            try:
                stack.enter_context(instance_lock.hold(data_dir))
            except instance_lock.InstanceLocked:
                _die("stop the running GitMortem before --vacuum")
            except OSError as exc:
                _die(f"cannot use data directory {data_dir}: {_os_reason(exc)}")
        try:
            with _clean_errors():
                engine = (
                    _open_database(data_dir) if vacuum else _open_database_beside_a_server(data_dir)
                )
        except (DBAPIError, sqlite3.Error) as exc:
            _die(f"cannot use the database in {data_dir}: {_database_reason(exc)}")
        try:
            _clear_audit(engine, data_dir, older_than=older_than, yes=yes, vacuum=vacuum)
        except (DBAPIError, sqlite3.Error) as exc:
            _die(f"cannot use the database in {data_dir}: {_database_reason(exc)}")
        finally:
            engine.dispose()


def _clear_audit(
    engine: Engine, data_dir: Path, *, older_than: int | None, yes: bool, vacuum: bool
) -> None:
    before = None if older_than is None else datetime.now(UTC) - timedelta(days=older_than)
    if vacuum:
        try:
            check_temp_folder(engine, data_dir)
        except CompactRefused as exc:
            _die(f"The database cannot be compacted, so nothing was deleted: {exc}.")
    with make_session_factory(engine)() as session:
        count, up_to_id = audit.clearable(session, before=before)
    if count == 0:
        scope = "to delete" if older_than is None else f"older than {_days(older_than)}"
        console.fail(f"No audit events {scope}.")
        return
    if older_than is None or before is None:
        console.info(f"{_audit_events(count)}, every one.")
    else:
        console.info(
            f"{_audit_events(count)} older than {_days(older_than)}"
            f" (before {before:%Y-%m-%d %H:%M} UTC)."
        )
    if not yes:
        if not stdin_is_a_terminal():
            _die("No terminal to confirm at: pass --yes to delete without asking.")
        try:
            agreed = click.confirm("Delete them?", default=False)
        except click.Abort:
            click.echo()
            _die("Stopped: nothing deleted.")
        if not agreed:
            console.fail("Nothing deleted.")
            return
    trace: dict[str, AuditValue] = {
        "older_than_days": older_than,
        "before": None if before is None else before.isoformat(),
    }
    try:
        deleted = audit.clear_events(
            make_session_factory(write_engine(engine)),
            before=before,
            up_to_id=up_to_id,
            trace=trace,
        )
    except KeyboardInterrupt:
        _die("Stopped: the events deleted before it stopped are recorded in the audit log.")
    except (DBAPIError, sqlite3.Error) as exc:
        _die(
            f"The audit log was not cleared: {_database_reason(exc)}. The events deleted before"
            " it failed are recorded in the audit log."
        )
    if deleted == 0:
        console.fail("Nothing deleted: the events counted were already gone.")
        return
    console.ok(f"Deleted {_audit_events(deleted)}.")
    if not vacuum and not truncate_journal(engine):
        console.info(
            "The write-ahead log could not be emptied while GitMortem reads it; it empties "
            "at its next checkpoint."
        )
    if vacuum:
        database = data_dir / "gitmortem.sqlite3"
        size = _database_bytes(database)
        try:
            emptied = compact(engine, data_dir)
        except CompactRefused as exc:
            _die(f"The database was not compacted: {exc}.")
        console.ok(f"Database compacted: {_mib(size)} to {_mib(_database_bytes(database))}.")
        if not emptied:
            console.fail(
                "Another process has the database open: its write-ahead log is emptied once"
                " that one closes it."
            )


def _audit_events(count: int) -> str:
    return f"{count:,} audit {'event' if count == 1 else 'events'}"


def _days(count: int) -> str:
    return f"{count:,} {'day' if count == 1 else 'days'}"


def _database_reason(exc: Exception) -> str:
    return str(exc.orig) if isinstance(exc, DBAPIError) else str(exc)


def _database_bytes(database: Path) -> int:
    wal = database.with_name(database.name + "-wal")
    return database.stat().st_size + (wal.stat().st_size if wal.exists() else 0)


def _mib(size: int) -> str:
    return f"{size / (1 << 20):.1f} MiB"


def _os_reason(exc: OSError) -> str:
    where = f" on {exc.filename}" if exc.filename else ""
    return f"{exc.strerror or type(exc).__name__}{where}"


@main.command(
    "demo-corpus",
    help="Write a corpus of fake repos with planted fake secrets into an empty TARGET.",
)
@click.argument("target", type=click.Path(path_type=Path))
@click.option("--seed", default=DEFAULT_SEED, show_default=True, type=int)
@click.option(
    "--size",
    default=Size.DEMO.value,
    show_default=True,
    type=click.Choice([size.value for size in Size]),
)
@click.option(
    "--hostile",
    is_flag=True,
    help="Also write hostile repos for security tests. "
    "They run a command if git is used on them naively.",
)
def demo_corpus(target: Path, seed: int, size: str, hostile: bool) -> None:
    try:
        preflight(target, hostile=hostile)
    except (CorpusError, GitUnavailable) as exc:
        _die(str(exc))
    except OSError as exc:
        _die(f"pre-flight check failed ({_os_reason(exc)}); nothing was written")
    console.info(f"Writing the {size} corpus (seed {seed}) into {target}")
    incomplete = f"{target} is incomplete, delete it before trying again"
    try:
        manifest = generate(target, seed=seed, size=Size(size), hostile=hostile)
    except (CorpusError, GitUnavailable) as exc:
        _die(str(exc))
    except GitError as exc:
        _die(f"generation failed ({exc}); {incomplete}")
    except OSError as exc:
        _die(f"generation failed ({_os_reason(exc)}); {incomplete}")
    except ValidationError:
        _die(f"generation failed (internal generator error); {incomplete}")
    kinds = [repo.kind for repo in manifest.repos]
    roles = [secret.role for secret in manifest.secrets]
    console.ok(
        f"Wrote {len(kinds)} repos ({kinds.count(RepoKind.CLEAN)} clean, "
        f"{kinds.count(RepoKind.HOSTILE)} hostile): {roles.count(SecretRole.PLANTED)} planted "
        f"secrets, {roles.count(SecretRole.BAIT)} bait strings"
    )
    console.info(f"Scan root: {target}/repos")
