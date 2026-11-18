import codecs
import json
import re
from collections.abc import Iterable, Iterator
from typing import Any

from pydantic import AfterValidator

from gitmortem.scanning.tools import bounded

__all__ = [
    "BOUND_REFUSALS",
    "MAX_DEPTH",
    "MAX_ITEM_BYTES",
    "REFUSALS",
    "StreamRefused",
    "cut_to",
    "json_array_items",
    "json_lines",
    "line_heads",
    "within_bytes",
]

MAX_ITEM_BYTES = 16 << 20
MAX_DEPTH = 64

_TOKEN = re.compile(r"[^ \t\n\r]")
_BLANK = re.compile(rb"[ \t\r]*")
_NUMBER_TAIL = re.compile(r"[0-9.eE+-]*")
_DECODER = json.JSONDecoder()

_NOT_UTF8 = "the stream is not UTF-8"
_NOT_AN_ARRAY = "the stream is not a JSON array"
_ENDS_INSIDE = "the stream ends inside the array"
_NO_COMMA = "the array's items are not separated by commas"
_AFTER_THE_ARRAY = "the stream goes on after the array"
_NOT_JSON = "an item is not JSON, or the stream ends inside it"
_TOO_LARGE = "an item is larger than its bound in bytes"
_TOO_DEEP = "an item nests deeper than its bound"
BOUND_REFUSALS = frozenset({_TOO_LARGE, _TOO_DEEP})
REFUSALS = frozenset(
    {
        _NOT_UTF8,
        _NOT_AN_ARRAY,
        _ENDS_INSIDE,
        _NO_COMMA,
        _AFTER_THE_ARRAY,
        _NOT_JSON,
        _TOO_LARGE,
        _TOO_DEEP,
    }
)


class StreamRefused(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Decoded:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._utf8 = codecs.getincrementaldecoder("utf-8")()
        self.text = ""
        self.at = 0
        self.ended = False

    def pull(self, wanted: int) -> None:
        pieces: list[str] = []
        got = 0
        while got < wanted and not self.ended:
            chunk = next(self._chunks, None)
            try:
                if chunk is None:
                    self.ended = True
                    pieces.append(self._utf8.decode(b"", final=True))
                else:
                    pieces.append(self._utf8.decode(chunk))
                    got += len(chunk)
            except UnicodeDecodeError:
                raise StreamRefused(_NOT_UTF8) from None
        self.text = self.text[self.at :] + "".join(pieces)
        self.at = 0

    def peek(self) -> str:
        while True:
            found = _TOKEN.search(self.text, self.at)
            if found is not None:
                self.at = found.start()
                return found[0]
            self.at = len(self.text)
            if self.ended:
                return ""
            self.pull(1)


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children: Iterable[Any] = item.values()
        elif isinstance(item, list):
            children = item
        else:
            continue
        deepest = max(deepest, depth)
        stack.extend((child, depth + 1) for child in children)
    return deepest


def _checked(text: str, value: Any, max_bytes: int, max_depth: int) -> Any:
    if len(text.encode("utf-8")) > max_bytes:
        raise StreamRefused(_TOO_LARGE)
    if text.count("[") + text.count("{") > max_depth and _depth(value) > max_depth:
        raise StreamRefused(_TOO_DEEP)
    return value


def _may_go_on(value: Any, text: str, end: int) -> bool:
    number = isinstance(value, int | float) and not isinstance(value, bool)
    return number and _NUMBER_TAIL.fullmatch(text, end) is not None


def _item(text: _Decoded, max_bytes: int, max_depth: int) -> Any:
    while True:
        start = text.at
        try:
            value, end = _DECODER.raw_decode(text.text, start)
        except RecursionError:
            raise StreamRefused(_TOO_DEEP) from None
        except ValueError:
            end = None
        if end is not None and (text.ended or not _may_go_on(value, text.text, end)):
            text.at = end
            return _checked(text.text[start:end], value, max_bytes, max_depth)
        if text.ended:
            raise StreamRefused(_NOT_JSON)
        held = len(text.text[start:].encode("utf-8"))
        if held > max_bytes:
            raise StreamRefused(_TOO_LARGE)
        text.pull(max(held, 1))


def json_array_items(
    chunks: Iterable[bytes], *, max_item_bytes: int = MAX_ITEM_BYTES, max_depth: int = MAX_DEPTH
) -> Iterator[Any]:
    text = _Decoded(chunks)
    if text.peek() != "[":
        raise StreamRefused(_NOT_AN_ARRAY)
    text.at += 1
    if text.peek() == "]":
        text.at += 1
    else:
        while True:
            if text.peek() == "":
                raise StreamRefused(_ENDS_INSIDE)
            yield _item(text, max_item_bytes, max_depth)
            mark = text.peek()
            text.at += 1
            if mark == "]":
                break
            if mark != ",":
                raise StreamRefused(_ENDS_INSIDE if mark == "" else _NO_COMMA)
    if text.peek() != "":
        raise StreamRefused(_AFTER_THE_ARRAY)


def _line_value(line: bytes, max_bytes: int, max_depth: int) -> Any:
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        raise StreamRefused(_NOT_UTF8) from None
    try:
        value = json.loads(text)
    except RecursionError:
        raise StreamRefused(_TOO_DEEP) from None
    except ValueError:
        raise StreamRefused(_NOT_JSON) from None
    return _checked(text, value, max_bytes, max_depth)


def json_lines(
    chunks: Iterable[bytes], *, max_line_bytes: int = MAX_ITEM_BYTES, max_depth: int = MAX_DEPTH
) -> Iterator[Any]:
    pieces: list[bytes] = []
    held = 0
    for chunk in chunks:
        start = 0
        while True:
            end = chunk.find(b"\n", start)
            piece = chunk[start:] if end == -1 else chunk[start:end]
            held += len(piece)
            if held > max_line_bytes:
                raise StreamRefused(_TOO_LARGE)
            if piece:
                pieces.append(piece)
            if end == -1:
                break
            line = b"".join(pieces)
            pieces.clear()
            held = 0
            if _BLANK.fullmatch(line) is None:
                yield _line_value(line, max_line_bytes, max_depth)
            start = end + 1
    line = b"".join(pieces)
    if _BLANK.fullmatch(line) is None:
        yield _line_value(line, max_line_bytes, max_depth)


def within_bytes(limit: int) -> AfterValidator:
    def check(text: str) -> str:
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("not UTF-8") from None
        if size > limit:
            raise ValueError(f"over {limit} bytes")
        return text

    return AfterValidator(check)


def cut_to(limit: int) -> AfterValidator:
    return AfterValidator(lambda text: bounded(text, limit))


def line_heads(chunks: Iterable[bytes], size: int) -> Iterator[bytes]:
    head = bytearray()
    for chunk in chunks:
        start = 0
        while True:
            end = chunk.find(b"\n", start)
            piece = chunk[start:] if end == -1 else chunk[start:end]
            head += piece[: size - len(head)]
            if end == -1:
                break
            yield bytes(head)
            head.clear()
            start = end + 1
    if head:
        yield bytes(head)
