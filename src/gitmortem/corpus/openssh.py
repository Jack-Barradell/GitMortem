import base64
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_MAGIC = b"openssh-key-v1\x00"
_KEY_TYPE = b"ssh-ed25519"
_BLOCK = 8
_WRAP = 70


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def openssh_ed25519(private_bytes: bytes, check: int, comment: str) -> str:
    if len(private_bytes) != 32:
        raise ValueError("an Ed25519 private key is 32 bytes")
    if not 0 <= check < 2**32:
        raise ValueError("the check value is an unsigned 32-bit integer")
    public = (
        Ed25519PrivateKey.from_private_bytes(private_bytes)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    public_blob = _string(_KEY_TYPE) + _string(public)
    private = (
        struct.pack(">II", check, check)
        + _string(_KEY_TYPE)
        + _string(public)
        + _string(private_bytes + public)
        + _string(comment.encode())
    )
    private += bytes(range(1, -len(private) % _BLOCK + 1))
    blob = (
        _MAGIC
        + _string(b"none")
        + _string(b"none")
        + _string(b"")
        + struct.pack(">I", 1)
        + _string(public_blob)
        + _string(private)
    )
    body = base64.b64encode(blob).decode()
    lines = [body[i : i + _WRAP] for i in range(0, len(body), _WRAP)]
    begin = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    end = "-----END " + "OPENSSH PRIVATE KEY-----"
    return "\n".join([begin, *lines, end])
