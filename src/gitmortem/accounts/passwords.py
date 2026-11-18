import base64
import hashlib
import hmac
from functools import cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

PEPPERED = "gm-pepper$"
_hasher = PasswordHasher()


def _with_pepper(pepper: bytes, pw: str) -> str:
    return base64.b64encode(hmac.new(pepper, pw.encode("utf-8"), hashlib.sha256).digest()).decode()


def hash_password(pw: str, pepper: bytes | None = None) -> str:
    if pepper is None:
        return _hasher.hash(pw)
    return PEPPERED + _hasher.hash(_with_pepper(pepper, pw))


def verify_password(stored_hash: str, pw: str, pepper: bytes | None = None) -> bool:
    try:
        if stored_hash.startswith(PEPPERED):
            if pepper is None:
                return False
            return _hasher.verify(stored_hash.removeprefix(PEPPERED), _with_pepper(pepper, pw))
        return _hasher.verify(stored_hash, pw)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str, pepper: bytes | None = None) -> bool:
    if pepper is not None and not stored_hash.startswith(PEPPERED):
        return True
    return _hasher.check_needs_rehash(stored_hash.removeprefix(PEPPERED))


@cache
def _dummy_hash() -> str:
    return _hasher.hash("gitmortem timing equaliser")


def burn_verify_time(pw: str) -> None:
    verify_password(_dummy_hash(), pw)
