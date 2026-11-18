import re
from pathlib import Path

__all__ = [
    "BINARY_PROBE_BYTES",
    "FULL_HEX",
    "MATCH_LIMIT",
    "MAX_VIEW_BYTES",
    "OBJECT_ID",
    "git_env",
    "unquote_c_style",
]

FULL_HEX = re.compile(r"[0-9a-f]{40}")
OBJECT_ID = re.compile(rb"[0-9a-f]{40}")
BINARY_PROBE_BYTES = 8000
MAX_VIEW_BYTES = 10 << 20
MATCH_LIMIT = 16_384

_C_ESCAPES = {
    ord("a"): 0x07,
    ord("b"): 0x08,
    ord("t"): 0x09,
    ord("n"): 0x0A,
    ord("v"): 0x0B,
    ord("f"): 0x0C,
    ord("r"): 0x0D,
    ord('"'): 0x22,
    ord("\\"): 0x5C,
}
_OCTAL = frozenset(b"01234567")


def git_env(git_dir: Path) -> dict[str, str]:
    return {"GIT_DIR": str(git_dir), "GIT_COMMON_DIR": str(git_dir)}


def unquote_c_style(data: bytes) -> tuple[bytes, bytes] | None:
    if data[:1] != b'"':
        return None
    out = bytearray()
    at = 1
    while at < len(data):
        byte = data[at]
        if byte == 0x22:
            return bytes(out), data[at + 1 :]
        if byte != 0x5C:
            out.append(byte)
            at += 1
            continue
        escape = data[at + 1 : at + 2]
        if escape and escape[0] in _C_ESCAPES:
            out.append(_C_ESCAPES[escape[0]])
            at += 2
            continue
        digits = data[at + 1 : at + 4]
        if len(digits) == 3 and digits[0] in b"0123" and all(d in _OCTAL for d in digits):
            out.append(int(digits, 8))
            at += 4
            continue
        return None
    return None
