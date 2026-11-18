import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO

from gitmortem.scanning.settings import UploadLimits

LOCAL = b"PK\x03\x04"
CENTRAL = b"PK\x01\x02"
END = b"PK\x05\x06"
ZIP64_END = b"PK\x06\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
_END_BYTES = 22
_MAX_COMMENT = 0xFFFF
_LOCATOR_BYTES = 20
_ZIP64_END_BYTES = 56
_CENTRAL_BYTES = 46
_LOCAL_BYTES = 30
_ZIP64_EXTRA = 0x0001
_READ = 1 << 20
MAX_KEPT_ENTRIES = 500_000
MAX_NAME_BYTES = 4096
MAX_NAME_SEGMENTS = 256

STORED = 0
DEFLATED = 8
ENCRYPTED_FLAG = 0x1
UTF8_FLAG = 0x800
_UNIX = 3
_KIND_MASK = 0o170000
_REGULAR = 0o100000
_FOLDER = 0o040000


class ZipRefusal(StrEnum):
    NOT_A_ZIP = "not_a_zip"
    MULTI_DISK = "multi_disk"
    TRUNCATED = "truncated"
    TOO_MANY_ENTRIES = "too_many_entries"
    TOO_LARGE_UNPACKED = "too_large_unpacked"
    OVERLAPPING = "overlapping"
    BACKSLASH_NAMES = "backslash_names"
    ENCRYPTED = "encrypted"
    BAD_CENTRAL_DIRECTORY = "bad_central_directory"
    LONG_NAMES = "long_names"
    TOO_MANY_REPOSITORIES = "too_many_repositories"


class ZipRefused(Exception):
    def __init__(self, reason: ZipRefusal) -> None:
        super().__init__(f"the zip was refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ZipEntry:
    name: bytes
    offset: int
    data_offset: int
    compressed: int
    size: int
    method: int
    crc: int
    flags: int
    made_by: int
    external: int

    @property
    def is_folder(self) -> bool:
        return self.name.endswith(b"/")

    @property
    def is_special(self) -> bool:
        if self.made_by >> 8 != _UNIX:
            return False
        kind = (self.external >> 16) & _KIND_MASK
        return kind not in (0, _REGULAR, _FOLDER)

    @property
    def utf8(self) -> bool:
        return bool(self.flags & UTF8_FLAG)


@dataclass(frozen=True)
class ZipListing:
    entries: tuple[ZipEntry, ...]
    total_entries: int
    declared_bytes: int


def _exact(reader: BinaryIO, at: int, count: int) -> bytes:
    reader.seek(at)
    data = reader.read(count)
    if len(data) != count:
        raise ZipRefused(ZipRefusal.TRUNCATED)
    return data


@dataclass(frozen=True)
class _End:
    entries: int
    directory_size: int
    directory_offset: int
    directory_end: int


def _end(reader: BinaryIO, size: int) -> _End:
    tail_bytes = min(size, _END_BYTES + _MAX_COMMENT)
    tail = _exact(reader, size - tail_bytes, tail_bytes)
    at = tail.rfind(END)
    while at != -1:
        (comment,) = struct.unpack_from("<H", tail, at + 20)
        if at + _END_BYTES + comment == tail_bytes:
            break
        at = tail.rfind(END, 0, at)
    if at == -1:
        raise ZipRefused(ZipRefusal.NOT_A_ZIP)
    end_at = size - tail_bytes + at
    disk, directory_disk, on_disk, entries, directory_size, directory_offset = struct.unpack_from(
        "<HHHHII", tail, at + 4
    )
    if 0xFFFF not in (disk, directory_disk, on_disk, entries) and 0xFFFFFFFF not in (
        directory_size,
        directory_offset,
    ):
        if disk or directory_disk or on_disk != entries:
            raise ZipRefused(ZipRefusal.MULTI_DISK)
        return _End(entries, directory_size, directory_offset, end_at)
    if end_at < _LOCATOR_BYTES:
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    locator = _exact(reader, end_at - _LOCATOR_BYTES, _LOCATOR_BYTES)
    if not locator.startswith(ZIP64_LOCATOR):
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    record_disk, record_at, disks = struct.unpack_from("<IQI", locator, 4)
    if record_disk or disks != 1:
        raise ZipRefused(ZipRefusal.MULTI_DISK)
    if record_at + _ZIP64_END_BYTES > end_at - _LOCATOR_BYTES:
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    record = _exact(reader, record_at, _ZIP64_END_BYTES)
    if not record.startswith(ZIP64_END):
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    (disk64, directory_disk64, on_disk64, entries64, size64, offset64) = struct.unpack_from(
        "<IIQQQQ", record, 16
    )
    if disk64 or directory_disk64 or on_disk64 != entries64:
        raise ZipRefused(ZipRefusal.MULTI_DISK)
    return _End(entries64, size64, offset64, record_at)


def _zip64_fields(
    extra: bytes, size: int, compressed: int, offset: int, disk: int
) -> tuple[int, int, int, int]:
    at = 0
    while at + 4 <= len(extra):
        kind, length = struct.unpack_from("<HH", extra, at)
        body = extra[at + 4 : at + 4 + length]
        at += 4 + length
        if kind != _ZIP64_EXTRA:
            continue
        values: list[int | None] = []
        read = 0
        wanted = [
            (size == 0xFFFFFFFF, 8),
            (compressed == 0xFFFFFFFF, 8),
            (offset == 0xFFFFFFFF, 8),
            (disk == 0xFFFF, 4),
        ]
        for needed, width in wanted:
            if not needed:
                values.append(None)
                continue
            if read + width > len(body):
                raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
            values.append(int.from_bytes(body[read : read + width], "little"))
            read += width
        return (
            size if values[0] is None else values[0],
            compressed if values[1] is None else values[1],
            offset if values[2] is None else values[2],
            disk if values[3] is None else values[3],
        )
    if 0xFFFFFFFF in (size, compressed, offset) or disk == 0xFFFF:
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    return size, compressed, offset, disk


@dataclass(slots=True)
class _Record:
    name: bytes
    offset: int
    compressed: int
    size: int
    method: int
    crc: int
    flags: int
    made_by: int
    external: int


def _records(reader: BinaryIO, end: _End) -> Iterator[_Record]:
    at = end.directory_offset
    stop = end.directory_offset + end.directory_size
    buffer = b""
    pos = 0
    reader.seek(at)

    def fill(wanted: int) -> None:
        nonlocal buffer, pos, at
        while len(buffer) - pos < wanted and at < stop:
            chunk = reader.read(min(_READ, stop - at))
            if not chunk:
                raise ZipRefused(ZipRefusal.TRUNCATED)
            at += len(chunk)
            buffer = buffer[pos:] + chunk
            pos = 0

    while True:
        fill(_CENTRAL_BYTES)
        if pos == len(buffer):
            return
        if len(buffer) - pos < _CENTRAL_BYTES or buffer[pos : pos + 4] != CENTRAL:
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        (
            made_by,
            _needed,
            flags,
            method,
            _time,
            _date,
            crc,
            compressed,
            size,
            name_bytes,
            extra_bytes,
            comment_bytes,
            disk,
            _internal,
            external,
            offset,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", buffer, pos + 4)
        whole = _CENTRAL_BYTES + name_bytes + extra_bytes + comment_bytes
        fill(whole)
        if len(buffer) - pos < whole:
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        name_at = pos + _CENTRAL_BYTES
        name = buffer[name_at : name_at + name_bytes]
        extra = buffer[name_at + name_bytes : name_at + name_bytes + extra_bytes]
        size, compressed, offset, disk = _zip64_fields(extra, size, compressed, offset, disk)
        if disk:
            raise ZipRefused(ZipRefusal.MULTI_DISK)
        pos += whole
        yield _Record(name, offset, compressed, size, method, crc, flags, made_by, external)


def _located(reader: BinaryIO, kept: list[_Record], end: _End) -> tuple[ZipEntry, ...]:
    entries: list[ZipEntry] = []
    reached = 0
    for record in sorted(kept, key=lambda r: r.offset):
        if record.offset < reached:
            raise ZipRefused(ZipRefusal.OVERLAPPING)
        header = _exact(reader, record.offset, _LOCAL_BYTES)
        if not header.startswith(LOCAL):
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        name_bytes, extra_bytes = struct.unpack_from("<HH", header, 26)
        if _exact(reader, record.offset + _LOCAL_BYTES, name_bytes) != record.name:
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        data_offset = record.offset + _LOCAL_BYTES + name_bytes + extra_bytes
        reached = data_offset + record.compressed
        if reached > end.directory_offset:
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        entries.append(
            ZipEntry(
                name=record.name,
                offset=record.offset,
                data_offset=data_offset,
                compressed=record.compressed,
                size=record.size,
                method=record.method,
                crc=record.crc,
                flags=record.flags,
                made_by=record.made_by,
                external=record.external,
            )
        )
    return tuple(entries)


def list_zip(
    reader: BinaryIO, size: int, limits: UploadLimits, keep: Callable[[bytes], bool]
) -> ZipListing:
    if size < _END_BYTES:
        raise ZipRefused(ZipRefusal.NOT_A_ZIP)
    if _exact(reader, 0, 4) not in (LOCAL, END):
        raise ZipRefused(ZipRefusal.NOT_A_ZIP)
    end = _end(reader, size)
    if end.entries > limits.zip_entries:
        raise ZipRefused(ZipRefusal.TOO_MANY_ENTRIES)
    if end.directory_offset + end.directory_size != end.directory_end:
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    kept: list[_Record] = []
    declared = 0
    count = 0
    for record in _records(reader, end):
        count += 1
        if count > end.entries:
            raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
        declared += record.size
        if declared > limits.unpacked_bytes:
            raise ZipRefused(ZipRefusal.TOO_LARGE_UNPACKED)
        if b"\\" in record.name and keep(record.name.replace(b"\\", b"/")):
            raise ZipRefused(ZipRefusal.BACKSLASH_NAMES)
        if not keep(record.name):
            continue
        if record.flags & ENCRYPTED_FLAG:
            raise ZipRefused(ZipRefusal.ENCRYPTED)
        if len(record.name) > MAX_NAME_BYTES or record.name.count(b"/") >= MAX_NAME_SEGMENTS:
            raise ZipRefused(ZipRefusal.LONG_NAMES)
        if len(kept) == MAX_KEPT_ENTRIES:
            raise ZipRefused(ZipRefusal.TOO_MANY_ENTRIES)
        kept.append(record)
    if count != end.entries:
        raise ZipRefused(ZipRefusal.BAD_CENTRAL_DIRECTORY)
    return ZipListing(_located(reader, kept, end), count, declared)


def read_small(reader: BinaryIO, entry: ZipEntry, limit: int) -> bytes | None:
    if entry.size > limit or entry.compressed > limit + 1024:
        return None
    raw = _exact(reader, entry.data_offset, entry.compressed)
    if entry.method == STORED:
        data = raw
    elif entry.method == DEFLATED:
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            data = inflater.decompress(raw, entry.size + 1)
        except zlib.error:
            return None
    else:
        return None
    if len(data) != entry.size or zlib.crc32(data) != entry.crc:
        return None
    return data
