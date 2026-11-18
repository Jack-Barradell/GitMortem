import hashlib
import hmac
from typing import Any

from sqlalchemy import Engine

from gitmortem.accounts.passwords import PEPPERED
from gitmortem.crypto import Purpose, Sealer, SealError
from gitmortem.db import write_engine
from gitmortem.keys import KeyPurpose, derive_subkey

__all__ = ["KeyMismatch", "check_instance_key", "key_check", "remember_key_check"]

_LABEL = b"gitmortem instance key check"
MISMATCH = (
    "the instance key does not belong to this database: put back the key file it was made "
    "with, or point --key-file at it"
)
NEW_KEY = (
    "a new instance key was made beside a database that already holds data sealed with "
    "another: put back its key file, or point --key-file at it"
)
_SEALED = (
    ("secrets", "value_sealed", Purpose.SECRET_VALUE),
    ("findings", "match_sealed", Purpose.FINDING_MATCH),
    ("notes", "text_sealed", Purpose.NOTE_TEXT),
    ("custom_rules", "pattern_sealed", Purpose.RULE_PATTERN),
)
_HELD = ("secrets", "findings", "notes", "custom_rules", "tool_runs")


class KeyMismatch(Exception):
    pass


def key_check(key: bytes) -> str:
    return hmac.new(derive_subkey(key, KeyPurpose.KEY_CHECK), _LABEL, hashlib.sha256).hexdigest()


def _columns(raw: Any, table: str) -> set[str]:
    return {row[1] for row in raw.execute(f"PRAGMA table_info({table})")}


def _stored_check(raw: Any) -> str | None:
    if "key_check" not in _columns(raw, "instance_settings"):
        return None
    row = raw.execute("SELECT key_check FROM instance_settings WHERE id = 1").fetchone()
    return None if row is None else row[0]


def _opens_a_sealed_field(raw: Any, key: bytes) -> bool | None:
    sealer = Sealer(key)
    for table, column, purpose in _SEALED:
        if column not in _columns(raw, table):
            continue
        row = raw.execute(f"SELECT {column} FROM {table} LIMIT 1").fetchone()  # noqa: S608
        if row is None:
            continue
        try:
            sealer.open(row[0], purpose)
        except SealError:
            return False
        return True
    return None


def _holds_data(raw: Any) -> bool:
    for table in _HELD:
        if not _columns(raw, table):
            continue
        if raw.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():  # noqa: S608
            return True
    if "password_hash" not in _columns(raw, "users"):
        return False
    peppered = raw.execute(
        "SELECT 1 FROM users WHERE substr(password_hash, 1, ?) = ? LIMIT 1",
        (len(PEPPERED), PEPPERED),
    ).fetchone()
    return peppered is not None


def check_instance_key(engine: Engine, key: bytes, *, created: bool) -> None:
    with engine.connect() as connection:
        raw: Any = connection.connection.dbapi_connection
        stored = _stored_check(raw)
        if stored is not None:
            if not hmac.compare_digest(stored, key_check(key)):
                raise KeyMismatch(NEW_KEY if created else MISMATCH)
            return
        if created:
            if _holds_data(raw):
                raise KeyMismatch(NEW_KEY)
            return
        if _opens_a_sealed_field(raw, key) is False:
            raise KeyMismatch(MISMATCH)


def remember_key_check(engine: Engine, key: bytes) -> None:
    expected = key_check(key)
    with write_engine(engine).begin() as connection:
        raw: Any = connection.connection.dbapi_connection
        if _stored_check(raw) is not None:
            return
        raw.execute(
            "INSERT INTO instance_settings (id, key_check) VALUES (1, ?)"
            " ON CONFLICT (id) DO UPDATE SET key_check = excluded.key_check"
            " WHERE instance_settings.key_check IS NULL",
            (expected,),
        )
