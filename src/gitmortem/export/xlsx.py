import re
import unicodedata
import zipfile
from collections.abc import Sequence
from types import TracebackType
from typing import BinaryIO, Self
from xml.sax.saxutils import quoteattr

from gitmortem.export.cells import clean, cut_to_units, utf16_units, xlsx_text

MAX_SHEET_ROWS = 1_048_576
MAX_CELL_CHARS = 32_767
_NAME_CHARS = 31
_NOT_IN_NAMES = re.compile(r"[\[\]:*?/\\\x00-\x1f\x7f]")
_EDGES = " '\t"

_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
_SHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
_BOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"


class SheetFull(Exception):
    pass


_RESERVED = "history"


def _name_char(character: str) -> bool:
    if unicodedata.category(character) in {"Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp"}:
        return False
    return character not in "\ufffe\uffff"


def _trimmed(text: str, units: int) -> str:
    while True:
        cut = cut_to_units(text, units).strip(_EDGES)
        if cut == text:
            return cut
        text = cut


def sheet_name(text: str, taken: set[str]) -> str:
    plain = "".join(c if _name_char(c) else "_" for c in _NOT_IN_NAMES.sub("_", clean(text)))
    base = _trimmed(plain, _NAME_CHARS) or "Sheet"
    name = base
    n = 1
    held = {t.lower() for t in taken} | {_RESERVED}
    while name.lower() in held:
        n += 1
        suffix = f" {n}"
        name = (_trimmed(base, _NAME_CHARS - len(suffix)) or "Sheet") + suffix
    return name


def _column(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, rest = divmod(index - 1, 26)
        name = chr(65 + rest) + name
    return name


class SheetWriter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.rows = 0
        stream.write(f'{_XML}<worksheet xmlns="{_MAIN}"><sheetData>'.encode())

    def row(self, cells: Sequence[str]) -> None:
        if self.rows >= MAX_SHEET_ROWS:
            raise SheetFull
        for cell in cells:
            if utf16_units(cell) > MAX_CELL_CHARS:
                raise ValueError(f"a cell holds at most {MAX_CELL_CHARS} characters")
        self.rows += 1
        n = self.rows
        parts = [f'<row r="{n}">']
        for index, cell in enumerate(cells):
            parts.append(
                f'<c r="{_column(index)}{n}" t="inlineStr"><is><t xml:space="preserve">'
                f"{xlsx_text(cell)}</t></is></c>"
            )
        parts.append("</row>")
        self._stream.write("".join(parts).encode())

    def close(self) -> None:
        self._stream.write(b"</sheetData></worksheet>")
        self._stream.close()


class XlsxBook:
    def __init__(self, out: BinaryIO) -> None:
        self._zip = zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED)
        self._names: list[str] = []
        self._open: SheetWriter | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.close()

    def sheet(self, title: str) -> SheetWriter:
        self._close_sheet()
        name = sheet_name(title, set(self._names))
        self._names.append(name)
        path = f"xl/worksheets/sheet{len(self._names)}.xml"
        self._open = SheetWriter(self._zip.open(path, "w"))  # type: ignore[arg-type]
        return self._open

    def _close_sheet(self) -> None:
        if self._open is not None:
            self._open.close()
            self._open = None

    def close(self) -> None:
        self._close_sheet()
        if not self._names:
            self.sheet("Sheet")
            self._close_sheet()
        count = range(1, len(self._names) + 1)
        overrides = "".join(
            f'<Override PartName="/xl/worksheets/sheet{n}.xml" ContentType="{_SHEET_TYPE}"/>'
            for n in count
        )
        self._zip.writestr(
            "[Content_Types].xml",
            f'{_XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{_BOOK_TYPE}"/>'
            f"{overrides}</Types>",
        )
        self._zip.writestr(
            "_rels/.rels",
            f'{_XML}<Relationships xmlns="{_PACKAGE_RELS}"><Relationship Id="rId1" '
            f'Type="{_RELS}/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        )
        sheets = "".join(
            f'<sheet name={quoteattr(name)} sheetId="{n}" r:id="rId{n}"/>'
            for n, name in zip(count, self._names, strict=True)
        )
        self._zip.writestr(
            "xl/workbook.xml",
            f'{_XML}<workbook xmlns="{_MAIN}" xmlns:r="{_RELS}"><sheets>{sheets}</sheets>'
            "</workbook>",
        )
        links = "".join(
            f'<Relationship Id="rId{n}" Type="{_RELS}/worksheet" Target="worksheets/sheet{n}.xml"/>'
            for n in count
        )
        self._zip.writestr(
            "xl/_rels/workbook.xml.rels",
            f'{_XML}<Relationships xmlns="{_PACKAGE_RELS}">{links}</Relationships>',
        )
        self._zip.close()
