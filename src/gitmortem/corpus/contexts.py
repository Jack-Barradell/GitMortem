import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from gitmortem.corpus.fakes import BaitKind, FakeSecret, SecretType
from gitmortem.corpus.rng import Rng


class Context(StrEnum):
    ENV = "env"
    YAML = "yaml"
    INI = "ini"
    JSON = "json"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    SHELL = "shell"
    AWS_CREDENTIALS = "aws-credentials"
    PEM = "pem"
    MARKDOWN = "markdown"


@dataclass(frozen=True)
class RenderedFile:
    content: bytes = field(repr=False)
    spans: tuple[tuple[str, int, int], ...] = field(repr=False)


_COMMENTS = (
    "tuned for the nightly batch",
    "keep in sync with the deploy notes",
    "see the runbook before changing",
    "raised after the March load test",
    "owned by the platform team",
    "safe to change in staging",
    "read once at start up",
    "matches the reverse proxy",
)
_SENTENCES = (
    "The service reads these settings once at start up.",
    "Changes are rolled out by the platform team on weekdays.",
    "Run the smoke test after every deploy.",
    "Logs are shipped to the central collector every minute.",
    "The nightly batch takes about forty minutes on a quiet day.",
    "Ask in the team channel before changing the retry policy.",
    "Staging mirrors production except for the data volume.",
    "Older notes live in the wiki and may be out of date.",
)
_WORDS = (
    "orders",
    "inventory",
    "billing",
    "reports",
    "gateway",
    "scheduler",
    "importer",
    "exporter",
    "metrics",
    "mailer",
)
_LEVELS = ("debug", "info", "warning", "error")
_REGIONS = ("eu-west-2", "us-east-1", "ap-south-1", "eu-central-1")
_HOSTS = ("localhost", "cache.internal.example.com", "queue.internal.example.org")
_PATHS = ("/var/lib/app", "/srv/data", "/opt/service/cache", "/tmp/work")  # noqa: S108
_MODES = ("fast", "safe", "strict", "lenient")

_Setting = tuple[str, Callable[[Rng], str | int | bool]]
_SETTINGS: tuple[_Setting, ...] = (
    ("timeout", lambda r: r.between(1, 120)),
    ("retries", lambda r: r.between(1, 9)),
    ("workers", lambda r: r.between(1, 16)),
    ("log_level", lambda r: r.choice(_LEVELS)),
    ("region", lambda r: r.choice(_REGIONS)),
    ("host", lambda r: r.choice(_HOSTS)),
    ("port", lambda r: r.between(1024, 65535)),
    ("enabled", lambda r: bool(r.below(2))),
    ("data_dir", lambda r: r.choice(_PATHS)),
    ("mode", lambda r: r.choice(_MODES)),
)

_SECRET_NAMES: dict[SecretType | BaitKind, str] = {
    SecretType.AWS_ACCESS_KEY_ID: "aws_access_key_id",
    SecretType.AWS_SECRET_ACCESS_KEY: "aws_secret_access_key",
    SecretType.GITHUB_PAT: "github_token",
    SecretType.SLACK_BOT_TOKEN: "slack_bot_token",
    SecretType.SLACK_WEBHOOK_URL: "slack_webhook_url",
    SecretType.POSTGRES_URL: "database_url",
    SecretType.MYSQL_URL: "database_url",
    SecretType.MONGODB_URL: "mongo_uri",
    SecretType.PASSWORD: "db_password",
    SecretType.GENERIC_API_KEY: "api_key",
    SecretType.JWT: "session_jwt",
    SecretType.PRIVATE_KEY_EC: "private_key",
    SecretType.PRIVATE_KEY_PKCS8: "private_key",
    SecretType.PRIVATE_KEY_OPENSSH: "private_key",
    BaitKind.AWS_EXAMPLE: "aws_access_key_id",
    BaitKind.AWS_EXAMPLE_SECRET: "aws_secret_access_key",
    BaitKind.PLACEHOLDER: "api_key",
    BaitKind.SHA256_HEX: "checksum",
    BaitKind.UUID: "request_id",
    BaitKind.LOCKFILE_INTEGRITY: "integrity",
    BaitKind.BASE64_IMAGE: "logo_data",
    BaitKind.FIXTURE_KEY: "private_key",
}
_AWS_KINDS = {
    SecretType.AWS_ACCESS_KEY_ID,
    SecretType.AWS_SECRET_ACCESS_KEY,
    BaitKind.AWS_EXAMPLE_SECRET,
}
_AWS_LOWER_CONTEXTS = {Context.AWS_CREDENTIALS, Context.ENV, Context.INI}
_KEY_KINDS = {
    SecretType.PRIVATE_KEY_EC,
    SecretType.PRIVATE_KEY_PKCS8,
    SecretType.PRIVATE_KEY_OPENSSH,
    BaitKind.FIXTURE_KEY,
}


def _camel(name: str) -> str:
    first, *rest = name.split("_")
    return first + "".join(word.capitalize() for word in rest)


def _name_for(secret_name: str, context: Context, kind: SecretType | BaitKind) -> str:
    if kind in _AWS_KINDS and context in _AWS_LOWER_CONTEXTS:
        return secret_name
    match context:
        case Context.ENV | Context.PYTHON | Context.SHELL:
            return secret_name.upper()
        case Context.JAVASCRIPT:
            return _camel(secret_name)
        case _:
            return secret_name


def _plain(value: str | int | bool) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def _quoted(value: str | int | bool) -> str:
    return json.dumps(value) if not isinstance(value, bool) else str(value).lower()


def _setting(rng: Rng) -> tuple[str, str | int | bool]:
    name, draw = rng.choice(_SETTINGS)
    return name, draw(rng)


def _filler_line(context: Context, rng: Rng) -> str:
    if rng.below(3) == 0:
        text = rng.choice(_COMMENTS)
        match context:
            case Context.INI | Context.AWS_CREDENTIALS:
                return f"; {text}"
            case Context.JAVASCRIPT:
                return f"// {text}"
            case _:
                return f"# {text}"
    name, value = _setting(rng)
    match context:
        case Context.ENV | Context.SHELL:
            return f"{name.upper()}={_plain(value)}"
        case Context.YAML:
            return f"{name}: {_quoted(value)}"
        case Context.INI | Context.AWS_CREDENTIALS:
            return f"{name} = {_plain(value)}"
        case Context.PYTHON:
            return f"{name.upper()} = {_py_literal(value)}"
        case _:
            return f"const {_camel(name)} = {_quoted(value)};"


def _py_literal(value: str | int | bool) -> str:
    return str(value) if isinstance(value, bool) else _quoted(value)


def _fillers(context: Context, rng: Rng, low: int, high: int) -> list[str]:
    return [_filler_line(context, rng) for _ in range(rng.between(low, high))]


def _secret_line(context: Context, name: str, value: str) -> str:
    match context:
        case Context.ENV:
            return f"{name}={value}"
        case Context.SHELL:
            return f"export {name}='{value}'"
        case Context.YAML:
            return f"{name}: {_quoted(value)}"
        case Context.INI | Context.AWS_CREDENTIALS:
            return f"{name} = {value}"
        case Context.PYTHON:
            return f"{name} = {_quoted(value)}"
        case Context.JAVASCRIPT:
            return f"const {name} = {_quoted(value)};"
        case _:
            return f"  {json.dumps(name)}: {json.dumps(value)}"


@dataclass
class _Block:
    lines: list[str] = field(repr=False)
    first: int
    last: int
    value: str = field(repr=False)


def _claim(names: set[str], name: str, context: Context) -> None:
    if context is not Context.MARKDOWN:
        if name in names:
            raise ValueError(f"two values named {name} in one {context} file")
        names.add(name)


def _blocks(context: Context, secrets: Sequence[FakeSecret]) -> list[_Block]:
    blocks: list[_Block] = []
    names: set[str] = set()
    for secret in secrets:
        name = _name_for(_SECRET_NAMES[secret.kind], context, secret.kind)
        _claim(names, name, context)
        multiline = "\n" in secret.value
        if multiline and context is not Context.MARKDOWN:
            raise ValueError(f"a multi-line value cannot be written as {context}")
        if context is Context.MARKDOWN:
            body = secret.value.split("\n") if multiline else [f"{name} = {secret.value}"]
            fence = "```" if multiline else "```ini"
            lines = [fence, *body, "```"]
            blocks.append(_Block(lines, 1, len(body), secret.value))
        else:
            line = _secret_line(context, name, secret.value)
            if secret.value not in line:
                raise ValueError(f"{secret.kind} does not survive {context} quoting")
            blocks.append(_Block([line], 0, 0, secret.value))
    return blocks


def _render_pem(secrets: Sequence[FakeSecret]) -> RenderedFile:
    if len(secrets) != 1 or secrets[0].kind not in _KEY_KINDS:
        raise ValueError("a pem file holds exactly one private key")
    value = secrets[0].value
    return RenderedFile((value + "\n").encode(), ((value, 1, value.count("\n") + 1),))


def _render_json(blocks: list[_Block], rng: Rng) -> list[tuple[str, _Block | None]]:
    entries: list[tuple[str, _Block | None]] = []
    for block in blocks:
        for _ in range(rng.between(1, 3)):
            name, value = _setting(rng)
            entries.append((f"  {json.dumps(name)}: {json.dumps(value)}", None))
        entries.append((block.lines[0], block))
    name, value = _setting(rng)
    entries.append((f"  {json.dumps(name)}: {json.dumps(value)}", None))
    return entries


def render_file(context: Context, secrets: Sequence[FakeSecret], rng: Rng) -> RenderedFile:
    if context is Context.PEM:
        return _render_pem(secrets)
    blocks = _blocks(context, secrets)
    lines: list[str] = []
    spans: list[tuple[str, int, int]] = []

    def place(block: _Block) -> None:
        start = len(lines)
        lines.extend(block.lines)
        spans.append((block.value, start + block.first + 1, start + block.last + 1))

    if context is Context.JSON:
        entries = _render_json(blocks, rng)
        lines.append("{")
        for index, (text, block) in enumerate(entries):
            comma = "," if index < len(entries) - 1 else ""
            if block is not None:
                spans.append((block.value, len(lines) + 1, len(lines) + 1))
            lines.append(text + comma)
        lines.append("}")
        return RenderedFile(("\n".join(lines) + "\n").encode(), tuple(spans))

    lines.extend(_header(context, rng))
    for block in blocks:
        lines.extend(
            _fillers(context, rng, 1, 4) if context is not Context.MARKDOWN else _prose(rng)
        )
        place(block)
    lines.extend(_fillers(context, rng, 1, 4) if context is not Context.MARKDOWN else _prose(rng))
    return RenderedFile(("\n".join(lines) + "\n").encode(), tuple(spans))


_TRAILING_COMMENT = {
    Context.ENV: " # ",
    Context.YAML: " # ",
    Context.SHELL: " # ",
    Context.PYTHON: "  # ",
    Context.JAVASCRIPT: " // ",
}


def comment_values(rendered: RenderedFile, context: Context, text: str) -> RenderedFile:
    lead = _TRAILING_COMMENT.get(context)
    if lead is None:
        raise ValueError(f"a {context} file takes no trailing comment")
    lines = rendered.content.split(b"\n")
    for _, first, _ in rendered.spans:
        lines[first - 1] += (lead + text).encode()
    return RenderedFile(b"\n".join(lines), rendered.spans)


def _prose(rng: Rng) -> list[str]:
    return ["", *(rng.choice(_SENTENCES) for _ in range(rng.between(1, 3))), ""]


def _header(context: Context, rng: Rng) -> list[str]:
    match context:
        case Context.SHELL:
            return ["#!/bin/sh", "set -eu"]
        case Context.INI:
            return ["[app]"]
        case Context.AWS_CREDENTIALS:
            return [f"[{rng.choice(('default', 'ci', 'staging'))}]"]
        case Context.YAML:
            return ["---"]
        case Context.MARKDOWN:
            return [f"# Notes on the {rng.choice(_WORDS)} service"]
        case Context.PYTHON:
            return [f'"""Settings for the {rng.choice(_WORDS)} service."""']
        case Context.JAVASCRIPT:
            return ["'use strict';"]
        case _:
            return []


def _py_function(rng: Rng) -> list[str]:
    word = rng.choice(_WORDS)
    return [
        f"def load_{word}(value, factor={rng.between(2, 9)}):",
        f'    """Scale a {word} figure."""',
        f"    return value * factor + {rng.between(1, 99)}",
    ]


def _js_function(rng: Rng) -> list[str]:
    word = rng.choice(_WORDS)
    return [
        f"function load{word.capitalize()}(value) {{",
        f"  return value * {rng.between(2, 9)} + {rng.between(1, 99)};",
        "}",
    ]


def _filler_yaml(rng: Rng) -> list[str]:
    lines = ["---"]
    for _ in range(rng.between(2, 5)):
        lines.append(f"{rng.choice(_WORDS)}:")
        for _ in range(rng.between(1, 4)):
            name, value = _setting(rng)
            lines.append(f"  {name}: {_quoted(value)}")
    return lines


def _filler_markdown(rng: Rng) -> list[str]:
    lines = [f"# The {rng.choice(_WORDS)} service", ""]
    for _ in range(rng.between(2, 5)):
        lines.append(f"## {rng.choice(_WORDS).capitalize()}")
        lines.append("")
        lines.extend(rng.choice(_SENTENCES) for _ in range(rng.between(1, 3)))
        lines.append("")
    return lines


def _filler_json(rng: Rng) -> list[str]:
    doc = {rng.choice(_WORDS): dict(_setting(rng) for _ in range(rng.between(1, 4)))}
    for _ in range(rng.between(1, 3)):
        doc[rng.choice(_WORDS)] = dict(_setting(rng) for _ in range(rng.between(1, 4)))
    return json.dumps(doc, indent=2).splitlines()


def _filler_dockerfile(rng: Rng) -> list[str]:
    lines = [f"FROM python:3.{rng.between(10, 13)}-slim", f"WORKDIR /srv/{rng.choice(_WORDS)}"]
    for _ in range(rng.between(1, 3)):
        lines.append(f"ENV {_env_pair(rng)}")
    lines += ["COPY . .", "RUN pip install --no-cache-dir .", 'CMD ["python", "-m", "app"]']
    return lines


def _env_pair(rng: Rng) -> str:
    name, value = _setting(rng)
    return f"{name.upper()}={_plain(value)}"


def _filler_text(rng: Rng) -> list[str]:
    return [rng.choice(_SENTENCES) for _ in range(rng.between(3, 12))]


def _filler_python(rng: Rng) -> list[str]:
    lines = [f'"""The {rng.choice(_WORDS)} helpers."""', ""]
    for _ in range(rng.between(1, 3)):
        lines += [f"# {rng.choice(_COMMENTS)}", *_py_function(rng), ""]
    return lines


def _filler_javascript(rng: Rng) -> list[str]:
    lines = ["'use strict';", ""]
    for _ in range(rng.between(1, 3)):
        lines += [f"// {rng.choice(_COMMENTS)}", *_js_function(rng), ""]
    return lines


_FILLERS: dict[str, Callable[[Rng], list[str]]] = {
    "python": _filler_python,
    "javascript": _filler_javascript,
    "yaml": _filler_yaml,
    "markdown": _filler_markdown,
    "json": _filler_json,
    "dockerfile": _filler_dockerfile,
    "text": _filler_text,
}


def filler_file(kind: str, rng: Rng) -> bytes:
    try:
        build = _FILLERS[kind]
    except KeyError:
        raise ValueError(f"unknown filler kind {kind!r}") from None
    return ("\n".join(build(rng)) + "\n").encode()
