import csv
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, TextIO

from gitmortem.export.cells import clean, neutral_csv


def write_csv(header: Sequence[str], rows: Iterable[Sequence[str]], out: TextIO) -> None:
    out.write("\ufeff")
    writer = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([neutral_csv(clean(cell)) for cell in header])
    for row in rows:
        writer.writerow([neutral_csv(clean(cell)) for cell in row])


_LINE_BREAKS = re.compile("\r\n|[\n\r\u2028\u2029]")


def write_txt(
    preamble: Sequence[str],
    header: Sequence[str],
    groups: Sequence[tuple[str, Sequence[Sequence[str]]]],
    out: TextIO,
) -> None:
    for line in preamble:
        out.write(clean(line) + "\n")
    width = max((len(name) for name in header), default=0)
    for title, rows in groups:
        out.write(f"\n== {clean(title)} ==\n")
        for row in rows:
            out.write("\n")
            for name, cell in zip(header, row, strict=True):
                lines = _LINE_BREAKS.split(clean(cell))
                out.write(f"{name.ljust(width)}  {lines[0]}\n")
                for more in lines[1:]:
                    out.write(f"{' ' * width}  {more}\n")


def _cleaned(value: Any) -> Any:
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, Mapping):
        return {clean(str(key)): _cleaned(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_cleaned(item) for item in value]
    return value


def write_json(document: Mapping[str, object], out: TextIO) -> None:
    json.dump(_cleaned(document), out, ensure_ascii=False, indent=2)
    out.write("\n")
