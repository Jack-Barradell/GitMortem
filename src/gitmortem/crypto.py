import contextlib
import hashlib
import hmac
import io
import os
import re
import tempfile
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gitmortem.keys import KEY_BYTES, KeyPurpose, derive_subkey

SEAL_VERSION = b"\x01"
NONCE_BYTES = 12
TAG_BYTES = 16
_AAD_PREFIX = b"gitmortem/v1/"

RAW_MAGIC = b"GMRAW1"
SALT_BYTES = 16
RAW_HEADER_BYTES = len(RAW_MAGIC) + SALT_BYTES
CHUNK_BYTES = 64 * 1024
_CIPHER_CHUNK_BYTES = CHUNK_BYTES + TAG_BYTES
_COUNTER_BYTES = 11
_RAW_FILE_INFO = b"gitmortem/raw-file/v1"
_PART = re.compile(r"[a-z0-9_-]{1,32}")


class SealError(Exception):
    def __init__(self) -> None:
        super().__init__("sealed data could not be opened")


class Purpose(StrEnum):
    SECRET_VALUE = "secrets.value"  # noqa: S105
    FINDING_VALUE = "findings.value"
    FINDING_MATCH = "findings.match"
    FINDING_MESSAGE = "findings.message"
    NOTE_TEXT = "notes.text"
    RULE_PATTERN = "custom_rules.pattern"
    CANARY_WORDS = "instance_settings.canary_words"


class Sealer:
    def __init__(self, instance_key: bytes) -> None:
        self._aead = AESGCM(derive_subkey(instance_key, KeyPurpose.FIELD))
        self._hash_key = derive_subkey(instance_key, KeyPurpose.VALUE_HASH)

    def seal(self, plaintext: bytes, purpose: Purpose) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        sealed = self._aead.encrypt(nonce, plaintext, _AAD_PREFIX + purpose.value.encode())
        return SEAL_VERSION + nonce + sealed

    def open(self, blob: bytes, purpose: Purpose) -> bytes:
        if len(blob) < 1 + NONCE_BYTES + TAG_BYTES or blob[:1] != SEAL_VERSION:
            raise SealError from None
        nonce = blob[1 : 1 + NONCE_BYTES]
        try:
            return self._aead.decrypt(
                nonce, blob[1 + NONCE_BYTES :], _AAD_PREFIX + purpose.value.encode()
            )
        except InvalidTag:
            raise SealError from None

    def value_hash(self, value: bytes) -> str:
        return hmac.new(self._hash_key, value, hashlib.sha256).hexdigest()


def _check_part(part: str) -> None:
    if _PART.fullmatch(part) is None:
        raise ValueError("raw store part must be 1 to 32 characters of a-z, 0-9, _ or -")


def _nonce(index: int, final: bool) -> bytes:
    return index.to_bytes(_COUNTER_BYTES, "big") + (b"\x01" if final else b"\x00")


def _open_chunk(aead: AESGCM, aad: bytes, index: int, sealed: bytes, *, final: bool) -> bytes:
    try:
        return aead.decrypt(_nonce(index, final), sealed, aad)
    except InvalidTag:
        raise SealError from None


def _sync_folder(folder: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


TEMP_PREFIX = ".tmp-"


def _remove_temporaries(folder: Path) -> None:
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        if name.startswith(TEMP_PREFIX):
            with contextlib.suppress(OSError):
                (folder / name).unlink()


class RawStore:
    def __init__(
        self, root: Path, instance_key: bytes, *, purpose: KeyPurpose = KeyPurpose.RAW_OUTPUT
    ) -> None:
        self._root = root
        self._key = derive_subkey(instance_key, purpose)

    def _path(self, scan_id: int, run_id: int, part: str) -> Path:
        _check_part(part)
        return self._root / str(scan_id) / f"{run_id}.{part}.gmr"

    def _file_aead(self, salt: bytes) -> AESGCM:
        key = HKDF(
            algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=_RAW_FILE_INFO
        ).derive(self._key)
        return AESGCM(key)

    @staticmethod
    def _aad(header: bytes, scan_id: int, run_id: int, part: str) -> bytes:
        return header + f"{scan_id}/{run_id}/{part}".encode()

    def write(self, scan_id: int, run_id: int, part: str, source: Path) -> None:
        target = self._path(scan_id, run_id, part)
        with source.open("rb") as src:
            self._seal(target, scan_id, run_id, part, src)

    def write_bytes(self, scan_id: int, run_id: int, part: str, data: bytes) -> None:
        self._seal(self._path(scan_id, run_id, part), scan_id, run_id, part, io.BytesIO(data))

    def _seal(self, target: Path, scan_id: int, run_id: int, part: str, src: BinaryIO) -> None:
        for folder in (self._root, target.parent):
            folder.mkdir(mode=0o700, exist_ok=True)
            if os.name == "posix":
                folder.chmod(0o700)
        salt = os.urandom(SALT_BYTES)
        header = RAW_MAGIC + salt
        aead = self._file_aead(salt)
        aad = self._aad(header, scan_id, run_id, part)
        descriptor, temp_name = tempfile.mkstemp(dir=target.parent, prefix=TEMP_PREFIX)
        try:
            with os.fdopen(descriptor, "wb") as out:
                out.write(header)
                index = 0
                current = src.read(CHUNK_BYTES)
                while True:
                    following = src.read(CHUNK_BYTES) if len(current) == CHUNK_BYTES else b""
                    final = not following
                    out.write(aead.encrypt(_nonce(index, final), current, aad))
                    if final:
                        break
                    current, index = following, index + 1
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp_name, target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        _sync_folder(target.parent)

    def read(self, scan_id: int, run_id: int, part: str) -> Iterator[bytes]:
        path = self._path(scan_id, run_id, part)
        with path.open("rb") as src:
            header = src.read(RAW_HEADER_BYTES)
            if len(header) != RAW_HEADER_BYTES or not header.startswith(RAW_MAGIC):
                raise SealError from None
            aead = self._file_aead(header[len(RAW_MAGIC) :])
            aad = self._aad(header, scan_id, run_id, part)
            body = os.fstat(src.fileno()).st_size - RAW_HEADER_BYTES
            count = max(1, -(-body // _CIPHER_CHUNK_BYTES))
            last_at = (count - 1) * _CIPHER_CHUNK_BYTES
            src.seek(RAW_HEADER_BYTES + last_at)
            last = _open_chunk(aead, aad, count - 1, src.read(body - last_at), final=True)
            src.seek(RAW_HEADER_BYTES)
            for index in range(count - 1):
                chunk = src.read(_CIPHER_CHUNK_BYTES)
                yield _open_chunk(aead, aad, index, chunk, final=False)
            yield last

    def read_tail(self, scan_id: int, run_id: int, part: str, most: int) -> tuple[bytes, int]:
        if most < 0:
            raise ValueError("a tail cannot be negative")
        path = self._path(scan_id, run_id, part)
        with path.open("rb") as src:
            header = src.read(RAW_HEADER_BYTES)
            if len(header) != RAW_HEADER_BYTES or not header.startswith(RAW_MAGIC):
                raise SealError from None
            aead = self._file_aead(header[len(RAW_MAGIC) :])
            aad = self._aad(header, scan_id, run_id, part)
            body = os.fstat(src.fileno()).st_size - RAW_HEADER_BYTES
            count = max(1, -(-body // _CIPHER_CHUNK_BYTES))
            size = body - count * TAG_BYTES
            if size < 0:
                raise SealError from None
            first = max(0, size - most) // CHUNK_BYTES
            pieces = []
            for index in range(first, count):
                at = index * _CIPHER_CHUNK_BYTES
                src.seek(RAW_HEADER_BYTES + at)
                final = index == count - 1
                sealed = src.read(body - at if final else _CIPHER_CHUNK_BYTES)
                pieces.append(_open_chunk(aead, aad, index, sealed, final=final))
        data = b"".join(pieces)
        return data[len(data) - min(most, len(data)) :], size

    def read_parts(self, scan_id: int, run_id: int, prefix: str, count: int) -> Iterator[bytes]:
        if count < 0:
            raise ValueError("a count of parts cannot be negative")
        names = [f"{prefix}-{number:05d}" for number in range(1, count + 1)]
        if not all(self._path(scan_id, run_id, name).is_file() for name in names):
            raise SealError
        for name in names:
            try:
                yield from self.read(scan_id, run_id, name)
            except FileNotFoundError:
                raise SealError from None

    def remove_parts(self, scan_id: int, run_id: int) -> None:
        folder = self._root / str(scan_id)
        for part in self.parts(scan_id, run_id):
            self._path(scan_id, run_id, part).unlink(missing_ok=True)
        _remove_temporaries(folder)
        try:
            folder.rmdir()
        except FileNotFoundError:
            return
        except OSError:
            return

    def sweep_temporaries(self) -> None:
        try:
            folders = os.listdir(self._root)
        except OSError:
            return
        for name in folders:
            folder = self._root / name
            if not folder.is_symlink() and folder.is_dir():
                _remove_temporaries(folder)

    def parts(self, scan_id: int, run_id: int) -> tuple[str, ...]:
        folder = self._root / str(scan_id)
        prefix, suffix = f"{run_id}.", ".gmr"
        try:
            names = os.listdir(folder)
        except FileNotFoundError:
            return ()
        found = (
            name.removeprefix(prefix).removesuffix(suffix)
            for name in names
            if name.startswith(prefix) and name.endswith(suffix)
        )
        return tuple(sorted(part for part in found if _PART.fullmatch(part)))
