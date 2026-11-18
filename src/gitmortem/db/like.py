ESCAPE = "\\"


def anywhere(text: str) -> str:
    for special in (ESCAPE, "%", "_"):
        text = text.replace(special, ESCAPE + special)
    return f"%{text}%"
