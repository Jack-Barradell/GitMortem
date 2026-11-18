import base64
import hashlib
import json
import math
import re
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gitmortem.corpus.errors import CorpusError
from gitmortem.corpus.openssh import openssh_ed25519
from gitmortem.corpus.rng import Rng

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"
_ALNUM = _UPPER + _LOWER + _DIGITS
_UPPER_ALNUM = _UPPER + _DIGITS
_BASE32 = _UPPER + "234567"
_AWS_SECRET_ALPHABET = _ALNUM + "/+"
_PASSWORD_ALPHABET = _ALNUM + "!#$%&()*+,-./:;<=>?@[]^_{|}~"
_P256_ORDER = (0xFFFFFFFF00000000FFFFFFFFFFFFFFFF << 128) | 0xBCE6FAADA7179E84F3B9CAC2FC632551
_EPOCH_BASE = 1609750800
_USERS = ("svc_app", "reporting", "deploy", "analytics", "billing")
_DATABASES = ("orders", "inventory", "accounts", "metrics", "users")
_NAMES = ("Ada Example", "Grace Sample", "Alan Demo", "Edsger Test")
_PLACEHOLDERS = ("your_api_key_here", "REPLACE_ME", "changeme", "xxxxxxxx")

_AWS_ID_ENTROPY = 3.25
_AWS_SECRET_ENTROPY = 4.5
_AWS_SECRET_LEADS = "/+"  # noqa: S105
_GENERIC_KEY_ENTROPY = 3.75
_HEX_STOP_WORDS = ("dead", "feed", "aaaaaa", "000000")
_SAFE_LEADS = "!%*@^~"
_GENERIC_KEYWORDS = (
    *("access", "api", "auth", "key", "credential", "creds"),
    *("passwd", "password", "secret", "token"),
)
_URL_PASSWORD_LEADS = _ALNUM.replace("x", "").replace("X", "")
_TOKEN_RUNS = (32, 60)
_BOX_KEYWORD = "box"
_MAX_DRAWS = 10_000
_RUN = re.compile("[A-Za-z0-9]+")


class SecretType(StrEnum):
    AWS_ACCESS_KEY_ID = "aws-access-key-id"
    AWS_SECRET_ACCESS_KEY = "aws-secret-access-key"  # noqa: S105
    GITHUB_PAT = "github-pat"
    SLACK_BOT_TOKEN = "slack-bot-token"  # noqa: S105
    SLACK_WEBHOOK_URL = "slack-webhook-url"
    PRIVATE_KEY_EC = "private-key-ec"
    PRIVATE_KEY_PKCS8 = "private-key-pkcs8"
    PRIVATE_KEY_OPENSSH = "private-key-openssh"
    POSTGRES_URL = "postgres-url"
    MYSQL_URL = "mysql-url"
    MONGODB_URL = "mongodb-url"
    PASSWORD = "password"  # noqa: S105
    GENERIC_API_KEY = "generic-api-key"
    JWT = "jwt"


class BaitKind(StrEnum):
    AWS_EXAMPLE = "aws-example"
    AWS_EXAMPLE_SECRET = "aws-example-secret"  # noqa: S105
    PLACEHOLDER = "placeholder"
    SHA256_HEX = "sha256-hex"
    UUID = "uuid"
    LOCKFILE_INTEGRITY = "lockfile-integrity"
    BASE64_IMAGE = "base64-image"
    FIXTURE_KEY = "fixture-key"


class Role(StrEnum):
    PLANTED = "planted"
    BAIT = "bait"


@dataclass(frozen=True)
class FakeSecret:
    kind: SecretType | BaitKind
    role: Role
    value: str = field(repr=False)
    parts: tuple[tuple[str, str], ...] = field(default=(), repr=False)


def _planted(kind: SecretType, value: str, parts: tuple[tuple[str, str], ...] = ()) -> FakeSecret:
    return FakeSecret(kind, Role.PLANTED, value, parts)


def _bait(kind: BaitKind, value: str, parts: tuple[tuple[str, str], ...] = ()) -> FakeSecret:
    return FakeSecret(kind, Role.BAIT, value, parts)


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _draw(
    kind: SecretType | BaitKind,
    rng: Rng,
    make: Callable[[Rng], str],
    keep: Callable[[str], bool],
) -> str:
    for _ in range(_MAX_DRAWS):
        value = make(rng)
        if keep(value):
            return value
    raise CorpusError(f"no {kind} value cleared its scanner gates in {_MAX_DRAWS} draws")


def _no_token_run(value: str) -> bool:
    return all(len(run) not in _TOKEN_RUNS for run in _RUN.findall(value))


def _password_kept(value: str) -> bool:
    lower = value.lower()
    return not any(word in lower for word in (*_GENERIC_KEYWORDS, _BOX_KEYWORD))


def _generic_key_kept(value: str) -> bool:
    return (
        _entropy(value) >= _GENERIC_KEY_ENTROPY
        and any(char in _DIGITS for char in value)
        and not any(word in value for word in _HEX_STOP_WORDS)
    )


def make_aws_pair(rng: Rng) -> tuple[FakeSecret, FakeSecret]:
    key_id = _draw(
        SecretType.AWS_ACCESS_KEY_ID,
        rng,
        lambda r: "AK" + "IA" + r.token(_BASE32, 16),
        lambda value: _entropy(value) >= _AWS_ID_ENTROPY,
    )
    secret = _draw(
        SecretType.AWS_SECRET_ACCESS_KEY,
        rng,
        lambda r: r.choice(_AWS_SECRET_LEADS) + r.token(_AWS_SECRET_ALPHABET, 39),
        lambda value: _entropy(value) >= _AWS_SECRET_ENTROPY and _no_token_run(value),
    )
    return (
        _planted(SecretType.AWS_ACCESS_KEY_ID, key_id),
        _planted(SecretType.AWS_SECRET_ACCESS_KEY, secret),
    )


def _pem(
    key: ec.EllipticCurvePrivateKey | Ed25519PrivateKey, fmt: serialization.PrivateFormat
) -> str:
    pem = key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption())
    return pem.decode().rstrip("\n")


def _ec_key(rng: Rng) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(1 + rng.below(_P256_ORDER - 1), ec.SECP256R1())


def _ec_pem(kind: SecretType | BaitKind, rng: Rng) -> str:
    return _draw(
        kind,
        rng,
        lambda r: _pem(_ec_key(r), serialization.PrivateFormat.TraditionalOpenSSL),
        _no_token_run,
    )


def _connection_url(scheme_host: str, rng: Rng) -> tuple[str, tuple[tuple[str, str], ...]]:
    user = rng.choice(_USERS)
    password = rng.choice(_URL_PASSWORD_LEADS) + rng.token(_ALNUM, 15)
    return scheme_host.format(
        creds=f"{user}:{password}", n=rng.between(1, 99), db=rng.choice(_DATABASES)
    ), (
        ("user", user),
        ("password", password),
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _jwt(rng: Rng) -> str:
    def encode(obj: dict[str, object]) -> str:
        return _b64url(json.dumps(obj, separators=(",", ":")).encode())

    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode(
        {"sub": rng.token(_DIGITS, 10), "name": rng.choice(_NAMES), "iat": _EPOCH_BASE}
    )
    signer = hmac.HMAC(rng.randbytes(32), hashes.SHA256())
    signer.update(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{_b64url(signer.finalize())}"


def make_secret(kind: SecretType, rng: Rng) -> FakeSecret:
    parts: tuple[tuple[str, str], ...] = ()
    match kind:
        case SecretType.AWS_ACCESS_KEY_ID | SecretType.AWS_SECRET_ACCESS_KEY:
            raise ValueError("the AWS types come as a pair: use make_aws_pair")
        case SecretType.GITHUB_PAT:
            value = "gh" + "p_" + rng.token(_ALNUM, 36)
        case SecretType.SLACK_BOT_TOKEN:
            value = (
                "xox"
                + "b-"
                + rng.token(_DIGITS, 11)
                + "-"
                + rng.token(_DIGITS, 12)
                + "-"
                + rng.token(_ALNUM, 24)
            )
        case SecretType.SLACK_WEBHOOK_URL:
            value = (
                "https://hooks.slack.com/services/T"
                + rng.token(_UPPER_ALNUM, 10)
                + "/B"
                + rng.token(_UPPER_ALNUM, 10)
                + "/"
                + rng.token(_ALNUM, 24)
            )
        case SecretType.PRIVATE_KEY_EC:
            value = _ec_pem(kind, rng)
        case SecretType.PRIVATE_KEY_PKCS8:
            value = _draw(
                kind,
                rng,
                lambda r: _pem(
                    Ed25519PrivateKey.from_private_bytes(r.randbytes(32)),
                    serialization.PrivateFormat.PKCS8,
                ),
                _no_token_run,
            )
        case SecretType.PRIVATE_KEY_OPENSSH:
            value = _draw(
                kind,
                rng,
                lambda r: openssh_ed25519(
                    r.randbytes(32), check=r.below(2**32), comment="deploy@example.com"
                ),
                _no_token_run,
            )
        case SecretType.POSTGRES_URL:
            value, parts = _connection_url(
                "postgres://{creds}@db-{n}.internal.example.com:5432/{db}", rng
            )
        case SecretType.MYSQL_URL:
            value, parts = _connection_url(
                "mysql://{creds}@db-{n}.internal.example.com:3306/{db}", rng
            )
        case SecretType.MONGODB_URL:
            value, parts = _connection_url("mongodb+srv://{creds}@cluster{n}.example.net/{db}", rng)
        case SecretType.PASSWORD:
            value = _draw(
                kind,
                rng,
                lambda r: r.choice(_SAFE_LEADS) + r.token(_PASSWORD_ALPHABET, 19),
                _password_kept,
            )
        case SecretType.GENERIC_API_KEY:
            value = _draw(kind, rng, lambda r: r.token(_DIGITS + "abcdef", 32), _generic_key_kept)
        case SecretType.JWT:
            value = _draw(kind, rng, _jwt, _no_token_run)
    return _planted(kind, value, parts)


def _aws_example() -> tuple[str, str]:
    return "AK" + "IAIOSFODNN7" + "EXAMPLE", "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY"


def make_bait(kind: BaitKind, rng: Rng) -> FakeSecret:
    parts: tuple[tuple[str, str], ...] = ()
    match kind:
        case BaitKind.AWS_EXAMPLE:
            key_id, secret = _aws_example()
            value, parts = key_id, (("access_key_id", key_id), ("secret_access_key", secret))
        case BaitKind.AWS_EXAMPLE_SECRET:
            value = _aws_example()[1]
        case BaitKind.PLACEHOLDER:
            value = rng.choice(_PLACEHOLDERS)
        case BaitKind.SHA256_HEX:
            value = hashlib.sha256(rng.randbytes(32)).hexdigest()
        case BaitKind.UUID:
            value = str(uuid.UUID(bytes=rng.randbytes(16), version=4))
        case BaitKind.LOCKFILE_INTEGRITY:
            value = _draw(
                kind,
                rng,
                lambda r: "sha512-" + base64.b64encode(r.randbytes(64)).decode(),
                _no_token_run,
            )
        case BaitKind.BASE64_IMAGE:
            value = _draw(
                kind,
                rng,
                lambda r: base64.b64encode(b"\x89PNG\r\n\x1a\n" + r.randbytes(120)).decode(),
                _no_token_run,
            )
        case BaitKind.FIXTURE_KEY:
            value = _ec_pem(kind, rng)
            parts = (("path", f"tests/fixtures/{rng.choice(_DATABASES)}_test_key.pem"),)
    return _bait(kind, value, parts)
