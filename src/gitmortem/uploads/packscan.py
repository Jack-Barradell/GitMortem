import threading
import zlib
from pathlib import Path
from typing import BinaryIO

__all__ = ["PackRefused", "PackScanCancelled", "check_pack"]

_CHUNK = 64 << 10
_FEED = 4 << 10
_HEAD_BYTES = 32
_OFS_DELTA = 6
_REF_DELTA = 7
_WHOLE = frozenset({1, 2, 3, 4})
_ID_BYTES = 20
_MAX_SHIFT = 63


class PackRefused(Exception):
    pass


class PackScanCancelled(Exception):
    pass


class _Stream:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self._buffer = b""
        self._at = 0

    def _more(self) -> bool:
        chunk = self._handle.read(_CHUNK)
        if not chunk:
            return False
        self._buffer = self._buffer[self._at :] + chunk
        self._at = 0
        return True

    def byte(self) -> int:
        if self._at >= len(self._buffer) and not self._more():
            raise PackRefused("the pack ends inside an object's header")
        value = self._buffer[self._at]
        self._at += 1
        return value

    def skip(self, count: int) -> None:
        while len(self._buffer) - self._at < count:
            if not self._more():
                raise PackRefused("the pack ends inside an object's base id")
        self._at += count

    def inflate(self, most: int) -> tuple[int, bytes]:
        inflater = zlib.decompressobj()
        produced = 0
        head = b""
        while not inflater.eof:
            if self._at >= len(self._buffer) and not self._more():
                raise PackRefused("the pack ends inside an object's data")
            piece = memoryview(self._buffer)[self._at : self._at + _FEED]
            try:
                out = inflater.decompress(piece, most + 1 - produced)
            except zlib.error:
                raise PackRefused("an object's data is not zlib") from None
            self._at += len(piece) - len(inflater.unconsumed_tail) - len(inflater.unused_data)
            if len(head) < _HEAD_BYTES:
                head += out[: _HEAD_BYTES - len(head)]
            produced += len(out)
            if produced > most:
                raise PackRefused("an object holds more than its header says")
        return produced, head


def _varint(data: bytes, at: int) -> tuple[int, int]:
    value, shift = 0, 0
    while True:
        if at >= len(data) or shift > _MAX_SHIFT:
            raise PackRefused("a delta's header cannot be read")
        byte = data[at]
        value |= (byte & 0x7F) << shift
        at += 1
        shift += 7
        if not byte & 0x80:
            return value, at


def check_pack(path: Path, *, most_bytes: int, ratio: int, cancel: threading.Event) -> None:
    size = path.stat().st_size
    total = 0
    with path.open("rb") as handle:
        header = handle.read(12)
        if len(header) != 12 or header[:4] != b"PACK":
            raise PackRefused("not a pack")
        if int.from_bytes(header[4:8], "big") not in (2, 3):
            raise PackRefused("a pack version git does not write")
        count = int.from_bytes(header[8:12], "big")
        stream = _Stream(handle)
        for _ in range(count):
            if cancel.is_set():
                raise PackScanCancelled
            byte = stream.byte()
            kind, length, shift = (byte >> 4) & 7, byte & 0x0F, 4
            while byte & 0x80:
                if shift > _MAX_SHIFT:
                    raise PackRefused("an object's size cannot be read")
                byte = stream.byte()
                length |= (byte & 0x7F) << shift
                shift += 7
            if length > most_bytes:
                raise PackRefused("an object is larger than an upload may hold")
            if kind == _OFS_DELTA:
                while stream.byte() & 0x80:
                    pass
            elif kind == _REF_DELTA:
                stream.skip(_ID_BYTES)
            elif kind not in _WHOLE:
                raise PackRefused("an object of no type git knows")
            produced, head = stream.inflate(length)
            if produced != length:
                raise PackRefused("an object holds less than its header says")
            made = length
            if kind in (_OFS_DELTA, _REF_DELTA):
                _, at = _varint(head, 0)
                made, _ = _varint(head, at)
            if made > most_bytes:
                raise PackRefused("an object would be larger than an upload may hold")
            total += made
            if total > ratio * max(size, 1):
                raise PackRefused("the pack's objects would be larger than its ratio allows")
