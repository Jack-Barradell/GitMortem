import io
import os
from collections import OrderedDict
from pathlib import Path

from gitmortem.crypto import RawStore, SealError
from gitmortem.keys import KeyPurpose
from gitmortem.scanning.imports import MAX_PIECE_BYTES
from gitmortem.uploads.place import private_folder

PIECE_BYTES = MAX_PIECE_BYTES
_RUN = 0
_CACHED = 2


class PieceUnreadable(Exception):
    def __init__(self) -> None:
        super().__init__("a sealed piece of the upload could not be opened")


class PieceStoreUnreachable(Exception):
    def __init__(self) -> None:
        super().__init__("a piece of the upload could not be read from the disk")


def _part(seq: int) -> str:
    return f"p{seq:06d}"


class UploadPieces:
    def __init__(self, root: Path, instance_key: bytes) -> None:
        self._root = root
        self._store = RawStore(root, instance_key, purpose=KeyPurpose.UPLOAD_PIECES)

    def write(self, upload_id: int, seq: int, data: bytes) -> None:
        if seq < 1 or not 1 <= len(data) <= PIECE_BYTES:
            raise ValueError("a piece is numbered from 1 and holds 1 to PIECE_BYTES bytes")
        private_folder(self._root.parent)
        self._store.write_bytes(upload_id, _RUN, _part(seq), data)

    def sweep_temporaries(self) -> None:
        self._store.sweep_temporaries()

    def read(self, upload_id: int, seq: int) -> bytes:
        try:
            return b"".join(self._store.read(upload_id, _RUN, _part(seq)))
        except SealError:
            raise PieceUnreadable from None
        except FileNotFoundError:
            raise PieceUnreadable from None
        except OSError:
            raise PieceStoreUnreachable from None

    def count(self, upload_id: int) -> int:
        return len(self._store.parts(upload_id, _RUN))

    def remove(self, upload_id: int) -> None:
        self._store.remove_parts(upload_id, _RUN)


class SealedZipReader(io.RawIOBase):
    def __init__(self, pieces: UploadPieces, upload_id: int, size: int) -> None:
        super().__init__()
        self._pieces = pieces
        self._upload_id = upload_id
        self._size = size
        self._at = 0
        self._cache: OrderedDict[int, bytes] = OrderedDict()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._at

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            at = offset
        elif whence == os.SEEK_CUR:
            at = self._at + offset
        elif whence == os.SEEK_END:
            at = self._size + offset
        else:
            raise ValueError("whence must be SEEK_SET, SEEK_CUR or SEEK_END")
        if at < 0:
            raise ValueError("a position cannot be negative")
        self._at = at
        return at

    def _piece(self, index: int) -> bytes:
        found = self._cache.get(index)
        if found is not None:
            self._cache.move_to_end(index)
            return found
        data = self._pieces.read(self._upload_id, index + 1)
        if len(data) != min(PIECE_BYTES, self._size - index * PIECE_BYTES):
            raise PieceUnreadable
        self._cache[index] = data
        if len(self._cache) > _CACHED:
            self._cache.popitem(last=False)
        return data

    def readinto(self, buffer: "bytearray | memoryview") -> int:  # type: ignore[override]
        view = memoryview(buffer).cast("B")
        want = min(len(view), max(0, self._size - self._at))
        done = 0
        while done < want:
            index, within = divmod(self._at, PIECE_BYTES)
            piece = self._piece(index)
            take = min(want - done, len(piece) - within)
            view[done : done + take] = piece[within : within + take]
            done += take
            self._at += take
        return done
