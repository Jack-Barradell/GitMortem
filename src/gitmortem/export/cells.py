import re

DX3_LEADING = ("=", "+", "-", "@", "\t", "\r")
_SURROGATE = re.compile("[\ud800-\udfff]")
_UNSAFE = re.compile("[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\ufffe\uffff]")
_LITERAL = re.compile("_(?=x[0-9A-Fa-f]{4})")
_BREAKS = re.compile("\r\n|[\r\u2028\u2029]")
_CONTROLS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufffe\uffff]"
)
_AFTER_A_BREAK = re.compile('(?<=[;\t\r\n"])(?=[=+\\-@])')


def clean(text: str) -> str:
    return _SURROGATE.sub("\ufffd", text)


def shown(text: str) -> str:
    return _CONTROLS.sub("\ufffd", _BREAKS.sub("\n", clean(text)))


def neutral(text: str) -> str:
    return "'" + text if text.startswith(DX3_LEADING) else text


def neutral_csv(text: str) -> str:
    return neutral(_AFTER_A_BREAK.sub("'", text))


def utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def cut_to_units(text: str, units: int) -> str:
    if utf16_units(text) <= units:
        return text
    kept, used = [], 0
    for character in text:
        size = 2 if ord(character) > 0xFFFF else 1
        if used + size > units:
            break
        kept.append(character)
        used += size
    return "".join(kept)


def xlsx_text(text: str) -> str:
    text = _LITERAL.sub("_x005F_", clean(text))
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _UNSAFE.sub(lambda found: f"_x{ord(found.group()):04X}_", text)
