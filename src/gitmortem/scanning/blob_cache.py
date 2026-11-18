from collections import OrderedDict

__all__ = ["BLOB_CACHE_BYTES", "BlobCache"]

BLOB_CACHE_BYTES = 64 << 20


class BlobCache:
    def __init__(self, limit: int = BLOB_CACHE_BYTES) -> None:
        self._held: OrderedDict[str, bytes] = OrderedDict()
        self._bytes = 0
        self._limit = limit

    def get(self, blob: str) -> bytes | None:
        found = self._held.get(blob)
        if found is not None:
            self._held.move_to_end(blob)
        return found

    def put(self, blob: str, content: bytes) -> None:
        if len(content) > self._limit or blob in self._held:
            return
        self._held[blob] = content
        self._bytes += len(content)
        while self._bytes > self._limit:
            _, dropped = self._held.popitem(last=False)
            self._bytes -= len(dropped)
