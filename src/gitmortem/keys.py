import base64
import binascii
import contextlib
import os
import stat
import tempfile
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gitmortem import paths, privacy
from gitmortem.config import Mode, Settings

KEY_BYTES = 32
LEFTOVER_PREFIX = ".instance-key-"
ENV_VAR = "GITMORTEM_INSTANCE_KEY"


class InstanceKeyError(Exception):
    pass


class KeyPurpose(StrEnum):
    SESSION = "session"
    THROTTLE = "throttle"
    DEVICE = "device"
    FIELD = "field"
    RAW_OUTPUT = "raw-output"
    VALUE_HASH = "value-hash"
    UPLOAD_PIECES = "upload-pieces"
    SESSION_KEY = "session-key"
    COOKIE_NAME = "cookie-name"
    KEY_CHECK = "key-check"
    PASSWORD = "password"  # noqa: S105


def _decode(text: str) -> bytes | None:
    try:
        raw = base64.urlsafe_b64decode(text.strip().encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        return None
    return raw if len(raw) == KEY_BYTES else None


def is_private(mode: int, owner_uid: int) -> bool:
    permissions = mode & 0o777
    if permissions & 0o077 == 0:
        return True
    return owner_uid == 0 and permissions & 0o037 == 0


def _require_private(path: Path) -> None:
    if os.name == "posix":
        status = path.stat()
        if not is_private(status.st_mode, status.st_uid):
            raise InstanceKeyError(
                f"instance key file {path} is accessible to other users (mode "
                f"{status.st_mode & 0o777:o}); make it private with: chmod 600 {path} (a mounted"
                f" secret may instead be root-owned with mode 0440), or pass the key in {ENV_VAR}"
            )
    try:
        privacy.require_private(
            path.resolve(), "instance key file", reading=True, hint=f"or pass the key in {ENV_VAR}"
        )
    except privacy.NotPrivate as exc:
        raise InstanceKeyError(str(exc)) from None


def _sync_folder(folder: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sweep_copies(path: Path, key: bytes) -> None:
    try:
        names = os.listdir(path.parent)
    except OSError:
        return
    for name in names:
        if not name.startswith(LEFTOVER_PREFIX):
            continue
        leftover = path.parent / name
        try:
            held = leftover.lstat()
            if not stat.S_ISREG(held.st_mode) or held.st_size > 256:
                continue
            if _decode(leftover.read_text(encoding="ascii")) == key:
                leftover.unlink()
        except (OSError, UnicodeDecodeError):
            continue


def _read_key_file(path: Path) -> bytes:
    try:
        _require_private(path)
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise InstanceKeyError(f"cannot read instance key file {path}: {exc}") from exc
    key = _decode(text)
    if key is None:
        raise InstanceKeyError(
            f"instance key file {path} is not a valid {KEY_BYTES}-byte key; "
            "restore it from a backup (it is never replaced automatically)"
        )
    return key


def load_or_create_key_file(path: Path) -> tuple[bytes, bool]:
    if path.exists():
        key = _read_key_file(path)
        _sweep_copies(path, key)
        return key, False
    key = os.urandom(KEY_BYTES)
    tmp_name: str | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=LEFTOVER_PREFIX)
        privacy.make_owner_only(Path(tmp_name))
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(base64.urlsafe_b64encode(key).decode("ascii") + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp_name, path)
    except FileExistsError:
        return _read_key_file(path), False
    except OSError as exc:
        raise InstanceKeyError(f"cannot create instance key file {path}: {exc}") from exc
    finally:
        if tmp_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
    with contextlib.suppress(OSError):
        _sync_folder(path.parent)
    return key, True


def load_key_from_env(environ: Mapping[str, str]) -> bytes | None:
    value = environ.get(ENV_VAR)
    if value is None:
        return None
    key = _decode(value)
    if key is None:
        raise InstanceKeyError(f"{ENV_VAR} is not a base64url-encoded {KEY_BYTES}-byte key")
    return key


def read_existing_key(path: Path, environ: Mapping[str, str]) -> bytes | None:
    env_key = load_key_from_env(environ)
    if env_key is not None:
        return env_key
    if not path.exists():
        return None
    return _read_key_file(path)


def resolve_instance_key(
    settings: Settings, environ: Mapping[str, str]
) -> tuple[bytes, Path | None]:
    if settings.mode is Mode.SERVER:
        env_key = load_key_from_env(environ)
        if env_key is not None:
            return env_key, None
        if settings.key_file is None:
            raise InstanceKeyError(f"server mode needs {ENV_VAR} or a key file")
        path = settings.key_file
    else:
        path = settings.key_file or paths.default_key_file()
    key, created = load_or_create_key_file(path)
    return key, path if created else None


def derive_subkey(master: bytes, purpose: KeyPurpose) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=b"gitmortem/" + purpose.value.encode(),
    ).derive(master)
