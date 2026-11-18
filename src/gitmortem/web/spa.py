import os
import secrets
from pathlib import Path
from typing import cast

from apiflask import APIBlueprint, abort
from flask import Response, current_app, send_from_directory
from werkzeug.security import safe_join

from gitmortem.web.security import public, set_style_nonce

STATIC_DIR = "gitmortem.static_dir"
NOT_BUILT = "The frontend is not built. Run: npm --prefix frontend run build"
_MIMETYPES = {".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css"}
NONCE_META = '<meta name="csp-nonce" content="{nonce}">'

MAX_NAME_BYTES = 255
MAX_PATH_BYTES = 1024

bp = APIBlueprint("spa", __name__, enable_openapi=False)


@bp.get("/")
@public
def index() -> Response:
    return _serve("")


@bp.get("/<path:path>", endpoint="path")
@public
def file_or_page(path: str) -> Response:
    return _serve(path)


def _serve(path: str) -> Response:
    if path == "api" or path.startswith("api/"):
        abort(404)
    root = cast(Path, current_app.extensions[STATIC_DIR])
    index = root / "index.html"
    if path:
        if len(path.encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES or any(
            len(part.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES
            for part in path.split("/")
        ):
            abort(404)
        candidate = safe_join(str(root), path)
        if candidate is not None and _is_file(Path(candidate)) and not _same(candidate, index):
            return send_from_directory(root, path, mimetype=_MIMETYPES.get(Path(path).suffix))
    if not index.is_file():
        abort(503, NOT_BUILT)
    return _app_page(index.read_text(encoding="utf-8"))


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except (OSError, ValueError):
        return False


def _same(candidate: str, index: Path) -> bool:
    try:
        return os.path.samefile(candidate, index)
    except (OSError, ValueError):
        return False


def _app_page(html: str) -> Response:
    if html.count("</head>") != 1:
        raise RuntimeError("index.html must contain exactly one </head> to carry the CSP nonce")
    nonce = secrets.token_urlsafe(18)
    set_style_nonce(nonce)
    page = html.replace("</head>", NONCE_META.format(nonce=nonce) + "</head>", 1)
    response = Response(page, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    return response
