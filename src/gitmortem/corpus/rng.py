import hashlib
from collections.abc import Sequence


class Rng:
    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._counter = 0
        self._buffer = b""

    @classmethod
    def from_seed(cls, seed: int) -> "Rng":
        return cls(str(seed).encode())

    def derive(self, label: str) -> "Rng":
        return Rng(hashlib.sha256(self._seed + b"/" + label.encode()).digest())

    def randbytes(self, n: int) -> bytes:
        while len(self._buffer) < n:
            block = self._seed + self._counter.to_bytes(8, "big")
            self._buffer += hashlib.sha256(block).digest()
            self._counter += 1
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("below() needs a positive bound")
        bits = (n - 1).bit_length()
        width = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            candidate = int.from_bytes(self.randbytes(width), "big") & mask
            if candidate < n:
                return candidate

    def between(self, lo: int, hi: int) -> int:
        if hi < lo:
            raise ValueError("between() needs lo <= hi")
        return lo + self.below(hi - lo + 1)

    def choice[T](self, items: Sequence[T]) -> T:
        if not items:
            raise ValueError("choice() from an empty sequence")
        return items[self.below(len(items))]

    def token(self, alphabet: str, length: int) -> str:
        if not alphabet:
            raise ValueError("token() needs a non-empty alphabet")
        return "".join(alphabet[self.below(len(alphabet))] for _ in range(length))
