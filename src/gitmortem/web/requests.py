import re
import traceback
from types import TracebackType
from typing import Any

from apiflask import APIFlask
from flask import Request, request
from werkzeug.routing import BaseConverter, ValidationError

__all__ = ["MAX_ID", "ApiRequest", "App", "IdConverter", "id_parameters"]

MAX_ID = 2**63 - 1
_MAX_ID_DIGITS = len(str(MAX_ID))
_SHOWN_PATH = 200
_UNSHOWN = re.compile(r"[^\x20-\x7e]")


class IdConverter(BaseConverter):
    regex = "[0-9]+"

    def to_python(self, value: str) -> int:
        if len(value) > _MAX_ID_DIGITS or int(value) > MAX_ID:
            raise ValidationError
        return int(value)

    def to_url(self, value: Any) -> str:
        return str(int(value))


class ApiRequest(Request):
    @property
    def want_form_data_parsed(self) -> bool:
        if self.path == "/api" or self.path.startswith("/api/"):
            return False
        return super().want_form_data_parsed


class App(APIFlask):
    request_class = ApiRequest

    def log_exception(
        self,
        exc_info: tuple[type[BaseException], BaseException, TracebackType]
        | tuple[None, None, None],
    ) -> None:
        kind, _, trace = exc_info
        if kind is None:
            return
        frames = " < ".join(
            f"{frame.filename}:{frame.lineno} {frame.name}"
            for frame in reversed(traceback.extract_tb(trace))
        )
        path = _UNSHOWN.sub("?", request.path)[:_SHOWN_PATH]
        self.logger.error("%s %s failed (%s) at %s", request.method, path, kind.__name__, frames)


def id_parameters(app: APIFlask, spec: dict[Any, Any]) -> dict[Any, Any]:
    named = {
        name
        for rule in app.url_map.iter_rules()
        for name, converter in rule._converters.items()
        if isinstance(converter, IdConverter)
    }
    for operations in spec.get("paths", {}).values():
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            for parameter in operation.get("parameters", []):
                if parameter.get("in") == "path" and parameter.get("name") in named:
                    parameter["schema"] = {"type": "integer"}
    return spec
