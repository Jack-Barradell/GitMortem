import contextlib
import errno
import grp
import ipaddress
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from string import Template
from typing import Protocol

from gitmortem.config import ConfigError, normalize_allowed_host
from gitmortem.install import caddy, scanners
from gitmortem.install.github import GitHub
from gitmortem.install.place import replace
from gitmortem.install.select import Choice

if sys.platform == "win32":
    raise ImportError("the server setup is for Ubuntu, not Windows")

__all__ = [
    "CADDYFILE",
    "CADDY_UNIT",
    "DATA",
    "KEY",
    "REPOS",
    "UNIT",
    "Account",
    "Admin",
    "RealSystem",
    "SetupPlan",
    "SetupRefused",
    "SetupResult",
    "System",
    "report",
    "setup",
]

OPT = Path("/opt/gitmortem")
TOOLS = OPT / "tools"
CURRENT = OPT / "current"
CADDY_RECORD = OPT / "caddy.json"
VAR = Path("/var/lib/gitmortem")
DATA = VAR / "data"
KEY = VAR / "instance.key"
REPOS = Path("/srv/gitmortem/repos")
UNIT = Path("/etc/systemd/system/gitmortem.service")
CADDY_UNIT = Path("/etc/systemd/system/caddy.service")
CADDYFILE = Path("/etc/caddy/Caddyfile")
CADDY_BIN = Path("/usr/local/bin/caddy")
SERVICE = "gitmortem"
CADDY = "caddy"
NO_HOME = Path("/nonexistent")
NOLOGIN = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"})
SYSTEM_UID_MAX = 999
MAX_PEM_BYTES = 1 << 20
UBUNTU = frozenset({"22.04", "24.04"})
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*")
_ARCHES: dict[str, scanners.Arch] = {"x86_64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}


class SetupRefused(Exception):
    pass


@dataclass(frozen=True)
class Admin:
    name: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class SetupPlan:
    address: str
    choice: Choice
    internal_tls: bool
    admin: Admin | None
    release: Path
    cert: Path | None = None
    key: Path | None = None


@dataclass(frozen=True)
class Account:
    uid: int
    home: str
    shell: str
    group: str | None
    locked: bool


@dataclass
class SetupResult:
    address: str
    kind: str
    https: bool
    changed: list[str]
    installed: list[scanners.Installed] = field(default_factory=list)


class System(Protocol):
    def path(self, real: Path) -> Path: ...
    def is_root(self) -> bool: ...
    def os_release(self) -> Mapping[str, str]: ...
    def machine(self) -> str: ...
    def has_package(self, name: str) -> bool: ...
    def account(self, name: str) -> Account | None: ...
    def is_enabled(self, unit: str) -> bool: ...
    def is_active(self, unit: str) -> bool: ...
    def run(self, argv: Sequence[str], *, stdin: bytes | None = None) -> None: ...
    def read(self, real: Path) -> bytes | None: ...
    def exists(self, real: Path) -> bool: ...
    def write(
        self, real: Path, data: bytes, *, mode: int, owner: str = "root", group: str | None = None
    ) -> bool: ...
    def read_pem(self, given: Path) -> bytes: ...
    def make_dir(
        self, real: Path, *, mode: int, owner: str = "root", group: str = "root"
    ) -> bool: ...
    def acl_has(self, real: Path, entry: str) -> bool: ...
    def link(self, target: Path, real: Path) -> bool: ...
    def has_admin(self, data_dir: Path) -> bool: ...
    def ask_admin(self) -> Admin: ...
    def https_ready(self, address: str, *, kind: caddy.Kind, seconds: int) -> bool: ...
    def say(self, line: str) -> None: ...


def _template(name: str) -> Template:
    return Template(files("gitmortem.install").joinpath("templates", name).read_text("utf-8"))


def _refuse_early(plan: SetupPlan, system: System) -> scanners.Arch:
    if not system.is_root():
        raise SetupRefused("setup-server sets up system services, so run it with sudo")
    release = system.os_release()
    arch = _ARCHES.get(system.machine())
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in UBUNTU or arch is None:
        seen = release.get("PRETTY_NAME") or f"{release.get('ID')} {release.get('VERSION_ID')}"
        raise SetupRefused(
            f"setup-server runs on Ubuntu 22.04 or 24.04 on x86_64 or arm64, not {seen} on "
            f"{system.machine()}"
        )
    try:
        if normalize_allowed_host(plan.address) != plan.address.lower():
            raise ConfigError("not a bare name")
        if not _plain_address(plan.address.lower()):
            raise ConfigError("not a hostname or an IPv4 address")
    except ConfigError:
        raise SetupRefused(
            f"{plan.address!r} is not an address GitMortem can answer to: give a domain name or "
            "an IPv4 address, with no scheme, port or path"
        ) from None
    return arch


def _plain_address(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        return address.isascii() and _HOSTNAME.fullmatch(address) is not None
    return True


def _packages(system: System, changed: list[str]) -> None:
    missing = [name for name in ("git", "acl", "ca-certificates") if not system.has_package(name)]
    if missing:
        system.run(["apt-get", "update", "-q"])
        system.run(["apt-get", "install", "-y", "-q", *missing])
        changed.append("packages")


def _refuse_account(name: str, held: Account) -> None:
    problems = []
    if not 0 < held.uid <= SYSTEM_UID_MAX:
        problems.append(f"is not a system account (uid {held.uid})")
    if held.shell not in NOLOGIN:
        problems.append(f"has the login shell {held.shell}")
    if not held.locked:
        problems.append("has a password that is not locked")
    if held.group != name:
        problems.append(f"has the primary group {held.group or 'unknown'}")
    if problems:
        raise SetupRefused(
            f"an account named {name} already exists and {', '.join(problems)}; the setup "
            "never runs GitMortem or Caddy as a login account. Remove or rename it first"
        )


def _accounts(system: System, changed: list[str]) -> None:
    for name, home in ((SERVICE, NO_HOME), (CADDY, Path("/var/lib/caddy"))):
        held = system.account(name)
        if held is None:
            system.run(
                [
                    "useradd",
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    str(home),
                    "--shell",
                    "/usr/sbin/nologin",
                    name,
                ]
            )
            changed.append(f"account {name}")
            continue
        _refuse_account(name, held)
        if name == SERVICE and held.home != str(NO_HOME):
            system.run(["usermod", "--home", str(NO_HOME), name])
            changed.append(f"{name}'s home")
    if system.make_dir(Path("/var/lib/caddy"), mode=0o700, owner=CADDY, group=CADDY):
        changed.append("caddy's home")


def _folders(system: System, changed: list[str]) -> None:
    for path, mode, owner in (
        (OPT, 0o755, "root"),
        (TOOLS, 0o755, "root"),
        (VAR, 0o700, SERVICE),
        (DATA, 0o700, SERVICE),
        (REPOS.parent, 0o755, "root"),
        (REPOS, 0o2770, SERVICE),
    ):
        if system.make_dir(path, mode=mode, owner=owner, group=owner):
            changed.append(str(path))
    for entry in ("-m g:gitmortem:rwX", "-d -m g:gitmortem:rwX"):
        if not system.acl_has(REPOS, entry):
            system.run(["setfacl", *entry.split(), str(REPOS)])
            changed.append(f"ACL {entry}")


def _install_scanners(
    plan: SetupPlan, system: System, github: GitHub, arch: scanners.Arch
) -> tuple[list[scanners.Installed], bool]:
    tools = system.path(TOOLS)
    record = tools / scanners.INSTALLED
    before = record.read_text(encoding="utf-8") if record.is_file() else ""
    if_missing = plan.choice == "known-good" and '"choice": "known-good"' in before
    platform = scanners.Platform("linux", arch)
    done = scanners.install(
        tools,
        plan.choice,
        github=github,
        platform=platform,
        if_missing=if_missing,
        folder_mode=0o755,
    )
    after = record.read_text(encoding="utf-8") if record.is_file() else ""
    return done, _shas(before) != _shas(after)


def _shas(record: str) -> list[str]:
    return [line for line in record.splitlines() if '"sha256"' in line]


def _install_caddy(system: System, github: GitHub, arch: str, changed: list[str]) -> bool:
    held = system.read(CADDY_RECORD)
    have = held.decode().strip() if held and system.exists(CADDY_BIN) else None
    staging = Path(tempfile.mkdtemp(prefix=".caddy-", dir=system.path(OPT)))
    try:
        staged = caddy.stage(github, arch, staging, have_sha512=have)
        if staged is None:
            return False
        final = system.path(CADDY_BIN)
        final.parent.mkdir(parents=True, exist_ok=True)
        replace(staged.new, final)
        system.write(CADDY_RECORD, staged.sha512.encode() + b"\n", mode=0o644)
        changed.append(f"caddy {staged.version}")
        return True
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(staging)


def _own_certificate(plan: SetupPlan, system: System, changed: list[str]) -> bool:
    if plan.cert is None or plan.key is None:
        return system.exists(caddy.TLS_CERT) and system.exists(caddy.TLS_KEY)
    cert, key = system.read_pem(plan.cert), system.read_pem(plan.key)
    done = system.make_dir(caddy.TLS_DIR, mode=0o750, owner="root", group=CADDY)
    done = system.write(caddy.TLS_CERT, cert, mode=0o644) or done
    done = system.write(caddy.TLS_KEY, key, mode=0o640, owner="root", group=CADDY) or done
    if done:
        changed.append("your certificate")
    return True


def _units(
    plan: SetupPlan, system: System, changed: list[str], *, own_cert: bool
) -> tuple[bool, bool]:
    gitmortem_unit = _template("gitmortem.service").substitute(address=plan.address.lower())
    caddy_unit = _template("caddy.service").substitute()
    caddyfile = _template("Caddyfile").substitute(
        site=caddy.site(plan.address.lower(), internal_tls=plan.internal_tls, own_cert=own_cert)
    )
    units = system.write(UNIT, gitmortem_unit.encode(), mode=0o644)
    caddy_changed = system.write(CADDY_UNIT, caddy_unit.encode(), mode=0o644)
    caddy_changed = system.make_dir(CADDYFILE.parent, mode=0o755) or caddy_changed
    caddy_changed = system.write(CADDYFILE, caddyfile.encode(), mode=0o644) or caddy_changed
    for done, name in ((units, "gitmortem's unit"), (caddy_changed, "caddy's unit or site")):
        if done:
            changed.append(name)
    return units, caddy_changed


def _first_admin(plan: SetupPlan, system: System, changed: list[str]) -> None:
    if system.has_admin(DATA):
        return
    admin = plan.admin or system.ask_admin()
    system.run(
        [
            "runuser",
            "-u",
            SERVICE,
            "--",
            str(CURRENT / "bin" / "gitmortem"),
            "create-admin",
            "--data-dir",
            str(DATA),
            "--username",
            admin.name,
            "--password-stdin",
        ],
        stdin=admin.password.encode() + b"\n",
    )
    changed.append("first admin")


def setup(plan: SetupPlan, *, system: System, github: GitHub) -> SetupResult:
    arch = _refuse_early(plan, system)
    changed: list[str] = []
    _packages(system, changed)
    _accounts(system, changed)
    _folders(system, changed)
    release_changed = system.link(plan.release, CURRENT)
    if release_changed:
        changed.append(f"current -> {plan.release}")
    installed, scanners_changed = _install_scanners(plan, system, github, arch)
    if scanners_changed:
        changed.append("scanners")
    caddy_binary = _install_caddy(system, github, arch, changed)
    own_cert = _own_certificate(plan, system, changed)
    gitmortem_unit, caddy_config = _units(plan, system, changed, own_cert=own_cert)
    _first_admin(plan, system, changed)
    if gitmortem_unit or caddy_config:
        system.run(["systemctl", "daemon-reload"])
    units = ("caddy.service", "gitmortem.service")
    if not all(system.is_enabled(unit) for unit in units):
        system.run(["systemctl", "enable", "--now", *units])
    else:
        if caddy_binary or caddy_config:
            system.run(["systemctl", "restart", "caddy.service"])
        if release_changed or gitmortem_unit or scanners_changed:
            system.run(["systemctl", "restart", "gitmortem.service"])
        stopped = [unit for unit in units if not system.is_active(unit)]
        if stopped:
            system.run(["systemctl", "start", *stopped])
            changed.append(f"started {', '.join(stopped)}")
    kind = caddy.certificate_kind(plan.address, internal_tls=plan.internal_tls, own_cert=own_cert)
    https = system.https_ready(plan.address.lower(), kind=kind, seconds=caddy.HTTPS_WAIT_SECONDS)
    return SetupResult(plan.address.lower(), kind, https, changed, installed)


def report(result: SetupResult) -> tuple[int, list[str]]:
    lines = [
        f"[*] changed: {', '.join(result.changed)}"
        if result.changed
        else "[*] nothing needed changing"
    ]
    if not result.https:
        lines.append(
            f"[!] no HTTPS answer from {result.address} within {caddy.HTTPS_WAIT_SECONDS} s. "
            "Check that ports 80 and 443 are open to this machine and that "
            f"{result.address} points at it; Caddy keeps trying, and running the setup again "
            "checks again. Everything else is in place."
        )
        return 1, lines
    lines.append(f"[+] GitMortem is at https://{result.address}/")
    if result.kind == "internal":
        lines.append(
            "[*] The certificate comes from Caddy's own certificate authority: copy "
            f"{caddy.INTERNAL_ROOT} to each colleague's machine and trust it, or browsers "
            "will warn."
        )
    elif result.kind == "shortlived":
        lines.append(
            "[*] The certificate is Let's Encrypt's short-lived one for an IP address; "
            "Caddy renews it."
        )
    elif result.kind == "own":
        lines.append(
            f"[*] Caddy serves your certificate from {caddy.TLS_DIR} (the key root:caddy, 0640), "
            "and the setup keeps it when run again. To renew it, run the setup again with "
            "--cert and --key; to go back to a certificate Caddy gets itself, delete "
            f"{caddy.TLS_CERT} and {caddy.TLS_KEY} and run the setup again."
        )
    lines += [
        f"[*] Repos brought in by hand go in {REPOS}, as the gitmortem user: "
        f"sudo -u gitmortem git clone <url> {REPOS}/<name>, or sudo -u gitmortem cp -r. "
        "GitMortem can write that folder, so a repository you own there could be given hooks "
        "your own git would run; one the gitmortem user owns makes your git refuse it.",
        f"[*] Back up {VAR} whole: the database and its key file travel together.",
        "[*] To upgrade: git fetch --tags, check out the new tag, and run "
        "sudo ./install.sh --server again.",
    ]
    return 0, lines


class RealSystem:
    def path(self, real: Path) -> Path:
        return real

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def os_release(self) -> Mapping[str, str]:
        found: dict[str, str] = {}
        with contextlib.suppress(OSError):
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                found[key.strip()] = value.strip().strip('"')
        return found

    def machine(self) -> str:
        return os.uname().machine

    def _query(self, argv: Sequence[str]) -> int:
        return subprocess.run(  # noqa: S603
            list(argv), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        ).returncode

    def has_package(self, name: str) -> bool:
        listed = subprocess.run(  # noqa: S603
            ["dpkg-query", "-W", "-f=${Status}", name],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return listed.endswith("install ok installed")

    def account(self, name: str) -> Account | None:
        try:
            held = pwd.getpwnam(name)
        except KeyError:
            return None
        try:
            group: str | None = grp.getgrgid(held.pw_gid).gr_name
        except KeyError:
            group = None
        status = subprocess.run(  # noqa: S603
            ["passwd", "--status", name],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        locked = len(status) > 1 and status[1] in ("L", "LK")
        return Account(held.pw_uid, held.pw_dir, held.pw_shell, group, locked)

    def is_enabled(self, unit: str) -> bool:
        return self._query(["systemctl", "is-enabled", "--quiet", unit]) == 0

    def is_active(self, unit: str) -> bool:
        return self._query(["systemctl", "is-active", "--quiet", unit]) == 0

    def run(self, argv: Sequence[str], *, stdin: bytes | None = None) -> None:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        done = subprocess.run(  # noqa: S603
            list(argv), input=stdin, stdout=subprocess.DEVNULL, check=False, env=env
        )
        if done.returncode != 0:
            raise SetupRefused(
                f"{argv[0]} failed (exit {done.returncode}); nothing after it was done"
            )

    def read(self, real: Path) -> bytes | None:
        try:
            return real.read_bytes()
        except OSError:
            return None

    def exists(self, real: Path) -> bool:
        return os.path.lexists(real)

    def _ids(self, owner: str, group: str) -> tuple[int, int]:
        return pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid

    def write(
        self, real: Path, data: bytes, *, mode: int, owner: str = "root", group: str | None = None
    ) -> bool:
        uid, gid = self._ids(owner, group or owner)
        with contextlib.suppress(OSError):
            held = real.stat()
            if (
                real.read_bytes() == data
                and (held.st_mode & 0o7777) == mode
                and (held.st_uid, held.st_gid) == (uid, gid)
            ):
                return False
        real.parent.mkdir(parents=True, exist_ok=True)
        new = real.with_name(f".{real.name}.new")
        new.unlink(missing_ok=True)
        fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.chown(new, uid, gid)
        os.chmod(new, mode)
        os.replace(new, real)
        return True

    def _open_folder(self, real: Path) -> tuple[int, bool]:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        made = False
        try:
            for name in real.parts[1:]:
                trusted = os.fstat(fd).st_uid == 0
                flags = os.O_RDONLY | os.O_DIRECTORY | (0 if trusted else os.O_NOFOLLOW)
                try:
                    nxt = os.open(name, flags, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(name, 0o755, dir_fd=fd)
                    made = True
                    nxt = os.open(name, flags | os.O_NOFOLLOW, dir_fd=fd)
                except OSError as error:
                    if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                        raise SetupRefused(
                            f"{real}: {name} is a link or not a folder where a folder must be; "
                            "the setup never follows one there"
                        ) from None
                    raise
                os.close(fd)
                fd = nxt
        except BaseException:
            os.close(fd)
            raise
        return fd, made

    def make_dir(self, real: Path, *, mode: int, owner: str = "root", group: str = "root") -> bool:
        uid, gid = self._ids(owner, group)
        fd, changed = self._open_folder(real)
        try:
            held = os.fstat(fd)
            if (held.st_uid, held.st_gid) != (uid, gid):
                os.fchown(fd, uid, gid)
                changed = True
            if (held.st_mode & 0o7777) != mode:
                os.fchmod(fd, mode)
                changed = True
        finally:
            os.close(fd)
        return changed

    def acl_has(self, real: Path, entry: str) -> bool:
        listed = subprocess.run(  # noqa: S603
            ["getfacl", "--omit-header", str(real)],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.splitlines()
        wanted = "default:group:gitmortem:rwx" if entry.startswith("-d") else "group:gitmortem:rwx"
        return wanted in listed

    def link(self, target: Path, real: Path) -> bool:
        if real.is_symlink() and Path(os.readlink(real)) == target:
            return False
        new = real.with_name(f".{real.name}.new")
        new.unlink(missing_ok=True)
        new.symlink_to(target)
        os.replace(new, real)
        return True

    def read_pem(self, given: Path) -> bytes:
        try:
            fd = os.open(given, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            raise SetupRefused(f"cannot read {given}: {exc.strerror}") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SetupRefused(f"{given} is not a regular file")
            data = os.read(fd, MAX_PEM_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_PEM_BYTES or b"-----BEGIN " not in data:
            raise SetupRefused(f"{given} is not a PEM file of at most 1 MiB")
        return data

    def has_admin(self, data_dir: Path) -> bool:
        done = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "runuser",
                "-u",
                SERVICE,
                "--",
                str(CURRENT / "bin" / "gitmortem"),
                "has-admin",
                "--data-dir",
                str(data_dir),
            ],
            stdout=subprocess.DEVNULL,
            check=False,
        )
        if done.returncode not in (0, 1):
            raise SetupRefused(
                f"could not tell whether {data_dir} holds an admin (exit {done.returncode})"
            )
        return done.returncode == 0

    def ask_admin(self) -> Admin:
        import click

        name = click.prompt("First admin's username")
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        return Admin(name, password)

    def https_ready(self, address: str, *, kind: caddy.Kind, seconds: int) -> bool:
        cafile = {"internal": caddy.INTERNAL_ROOT, "own": caddy.TLS_CERT}.get(kind)
        return caddy.wait_for_https(address, seconds=seconds, cafile=cafile)

    def say(self, line: str) -> None:
        print(line, flush=True)
