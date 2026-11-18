import functools
import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from apiflask import abort
from flask import Flask, Response, current_app, g, request, session
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_wtf import csrf as flask_wtf_csrf
from flask_wtf.csrf import CSRFError, CSRFProtect
from itsdangerous import TimestampSigner, URLSafeTimedSerializer

from gitmortem.accounts.refusals import RefusalKey, RefusalTally
from gitmortem.accounts.users import address_bucket
from gitmortem.db.models import Role, User
from gitmortem.web.dbsession import get_db
from gitmortem.web.schemas import MessageOut

IDLE_TIMEOUT = timedelta(hours=1)
ABSOLUTE_TIMEOUT = timedelta(hours=8)
LOGIN_AT = "login_at"
SEEN_AT = "seen_at"
REAUTH_AT = "reauth_at"
STEP_UP_WINDOW = timedelta(minutes=10)
PASSWORD_NEEDED = "Enter your password again to do this."  # noqa: S105
PASSWORD_CHANGE_NEEDED = "Change your password before doing anything else."  # noqa: S105
SESSION_HOST = "host"
KEY_MAC = "key_mac"
SESSION_KEY_HEADER = "X-GitMortem-Session"
BACKGROUND_HEADER = "X-GitMortem-Background"
SESSION_KEY_MAC = "GITMORTEM_SESSION_KEY_MAC"
SESSION_EXPIRED = "Session expired"
SESSION_KEY_REFUSED = "This request does not carry its session's key: sign in again."
CROSS_SITE = "Requests from another site are refused."
DUPLICATE_COOKIE = "The request carries its session cookie more than once."
_FOREIGN_SITES = frozenset({"cross-site", "same-site"})
CSRF_FAILED = "CSRF token missing or invalid."
NOT_JSON = "Request bodies must be JSON (Content-Type: application/json)."
JSON_TOO_DEEP = "The request body is nested too deeply."
MAX_JSON_DEPTH = 256
HSTS = "max-age=31536000"
_CSP_BEFORE_STYLE = ["default-src 'self'", "script-src 'self'"]
_CSP_AFTER_STYLE = [
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "require-trusted-types-for 'script'",
    "trusted-types vue gitmortem-worker",
]

THROTTLE_KEY = "GITMORTEM_THROTTLE_KEY"
PASSWORD_PEPPER = "GITMORTEM_PASSWORD_PEPPER"  # noqa: S105
SEND_HSTS = "GITMORTEM_SEND_HSTS"
TRUSTED_PROXY = "GITMORTEM_TRUSTED_PROXY"

_PUBLIC_MARK = "_gitmortem_public"
_ROLE_MARK = "_gitmortem_role"
_STEP_UP_MARK = "_gitmortem_step_up"
_BEFORE_CHANGE_MARK = "_gitmortem_before_password_change"
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CLOCK = "gitmortem.clock"
REFUSALS = "gitmortem.refusals"
_REFUSAL = "refusal"
_QUIET_SIGNED_OUT = frozenset({"auth.me"})
_USER_ID = "_user_id"
_SESSION_ID = re.compile(r"([0-9]{1,18})\.([0-9]{1,18})")
_RANK = {Role.ANALYST: 0, Role.ADMIN: 1}


@dataclass(frozen=True)
class SessionUser(UserMixin):  # type: ignore[misc]
    id: int
    username: str
    role: Role
    epoch: int
    must_change_password: bool = False

    @classmethod
    def from_user(cls, user: User) -> "SessionUser":
        return cls(
            id=user.id,
            username=user.username,
            role=user.role,
            epoch=user.session_epoch,
            must_change_password=user.must_change_password,
        )

    def get_id(self) -> str:
        return f"{self.id}.{self.epoch}"


def public[V: Callable[..., Any]](view: V) -> V:
    setattr(view, _PUBLIC_MARK, True)
    return view


def is_public_view(view: Callable[..., Any] | None) -> bool:
    return getattr(view, _PUBLIC_MARK, False) is True


def note_refusal(reason: str) -> None:
    setattr(g, _REFUSAL, reason)


def check_role(role: Role) -> None:
    if not current_user.is_authenticated:
        note_refusal("signed_out")
        abort(401)
    if _RANK[current_user.role] < _RANK[role]:
        note_refusal("role")
        abort(403)


def require_role[V: Callable[..., Any]](role: Role) -> Callable[[V], V]:
    def decorate(view: V) -> V:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check_role(role)
            return view(*args, **kwargs)

        setattr(wrapper, _ROLE_MARK, role)
        return cast(V, wrapper)

    return decorate


def require_recent_password[V: Callable[..., Any]](view: V) -> V:
    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not recently_reauthenticated(now()):
            abort(403, PASSWORD_NEEDED, detail={"reason": "password_needed"})
        return view(*args, **kwargs)

    setattr(wrapper, _STEP_UP_MARK, True)
    return cast(V, wrapper)


def needs_recent_password(view: Callable[..., Any] | None) -> bool:
    return getattr(view, _STEP_UP_MARK, False) is True


def allowed_before_password_change[V: Callable[..., Any]](view: V) -> V:
    setattr(view, _BEFORE_CHANGE_MARK, True)
    return view


def is_allowed_before_password_change(view: Callable[..., Any] | None) -> bool:
    return getattr(view, _BEFORE_CHANGE_MARK, False) is True


def recently_reauthenticated(moment: datetime) -> bool:
    stamp = _read_stamp(session.get(REAUTH_AT))
    return stamp is not None and timedelta(0) <= moment - stamp < STEP_UP_WINDOW


def mark_reauthenticated(moment: datetime) -> None:
    session[REAUTH_AT] = _stamp(moment)


def role_of(view: Callable[..., Any] | None) -> Role | None:
    role = getattr(view, _ROLE_MARK, None)
    return role if isinstance(role, Role) else None


class UnclassifiedRoutes(RuntimeError):
    def __init__(self, endpoints: Iterable[str]) -> None:
        self.endpoints = tuple(sorted(endpoints))
        super().__init__(
            "every route must be public or name its role; these do not: "
            + ", ".join(self.endpoints)
        )


def refuse_unclassified(app: Flask) -> None:
    unclassified = [
        endpoint
        for endpoint, view in app.view_functions.items()
        if not is_public_view(view) and role_of(view) is None
    ]
    if unclassified:
        raise UnclassifiedRoutes(unclassified)


def content_security_policy(style_nonce: str | None = None) -> str:
    style = "style-src 'self'" if style_nonce is None else f"style-src 'self' 'nonce-{style_nonce}'"
    return "; ".join([*_CSP_BEFORE_STYLE, style, *_CSP_AFTER_STYLE])


def set_style_nonce(nonce: str) -> None:
    g.style_nonce = nonce


def now() -> datetime:
    clock = cast(Callable[[], datetime], current_app.extensions[_CLOCK])
    return clock()


def client_ip() -> str | None:
    if current_app.config.get(TRUSTED_PROXY) is not None:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded is not None:
            return parse_address(forwarded.split(",")[-1])
    return parse_address(request.remote_addr or "")


def parse_address(raw: str) -> str | None:
    text = raw.strip().strip('"')
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            return None
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
    return str(address)


def throttle_key() -> bytes:
    return cast(bytes, current_app.config[THROTTLE_KEY])


def password_pepper() -> bytes:
    return cast(bytes, current_app.config[PASSWORD_PEPPER])


def _key_mac(key: str) -> str:
    secret = cast(bytes, current_app.config[SESSION_KEY_MAC])
    return hmac.new(secret, key.encode("utf-8"), hashlib.sha256).hexdigest()


def start_session(user: User, now: datetime) -> str:
    if not user.is_active:
        raise ValueError("cannot start a session for an inactive user")
    stamp = _stamp(now)
    key = secrets.token_urlsafe(32)
    session.clear()
    session.permanent = True
    login_user(SessionUser.from_user(user))
    session[LOGIN_AT] = session[SEEN_AT] = session[REAUTH_AT] = stamp
    session[SESSION_HOST] = request.host
    session[KEY_MAC] = _key_mac(key)
    return key


def _key_matches() -> bool:
    held = session.get(KEY_MAC)
    given = request.headers.get(SESSION_KEY_HEADER, "")
    if not isinstance(held, str) or not given or len(given) > 256:
        return False
    return hmac.compare_digest(_key_mac(given), held)


def end_session() -> None:
    session.clear()
    logout_user()


def install_guard(app: Flask, clock: Callable[[], datetime]) -> None:
    app.extensions[_CLOCK] = clock
    manager = LoginManager()
    manager.user_loader(_load_user)
    manager.init_app(app, add_context_processor=False)
    app.before_request(_guard)


class _Sha256Signer(TimestampSigner):
    default_digest_method = staticmethod(hashlib.sha256)


class Sha256Serializer(URLSafeTimedSerializer):
    default_signer = _Sha256Signer


def install_csrf(app: Flask) -> None:
    flask_wtf_csrf.URLSafeTimedSerializer = Sha256Serializer
    CSRFProtect(app)
    app.register_error_handler(CSRFError, _csrf_failed)


def install_json_only(app: Flask) -> None:
    app.before_request(_require_json)


def install_headers(app: Flask) -> None:
    app.after_request(_security_headers)


def install_refusal_count(app: Flask, tally: RefusalTally) -> None:
    app.extensions[REFUSALS] = tally
    app.after_request(_count_refusal)


def _count_refusal(response: Response) -> Response:
    reason = g.pop(_REFUSAL, None)
    if not isinstance(reason, str):
        return response
    endpoint = request.endpoint or ""
    if reason == "signed_out" and endpoint in _QUIET_SIGNED_OUT:
        return response
    tally = cast(RefusalTally, current_app.extensions[REFUSALS])
    loaded = g.get("_login_user")
    user_id = loaded.id if loaded is not None and loaded.is_authenticated else None
    key = RefusalKey(user_id, address_bucket(client_ip()), endpoint or "unrouted", reason)
    tally.add(key, now())
    return response


def _stamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("naive datetime rejected: session times must be timezone-aware")
    return moment.astimezone(UTC).isoformat()


def _read_stamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _load_user(session_id: object) -> SessionUser | None:
    if not isinstance(session_id, str):
        return None
    match = _SESSION_ID.fullmatch(session_id)
    if match is None:
        return None
    user = get_db().get(User, int(match[1]))
    if user is None or not user.is_active:
        return None
    candidate = SessionUser.from_user(user)
    return candidate if candidate.get_id() == session_id else None


def _guard() -> None:
    api = _is_api(request.path)
    if api and request.headers.get("Sec-Fetch-Site") in _FOREIGN_SITES:
        note_refusal("cross_site")
        abort(403, CROSS_SITE)
    if api and len(request.cookies.getlist(current_app.config["SESSION_COOKIE_NAME"])) > 1:
        note_refusal("duplicate_cookie")
        abort(400, DUPLICATE_COOKIE)
    endpoint = request.endpoint
    if endpoint is None:
        return
    is_public = is_public_view(current_app.view_functions.get(endpoint))
    if not is_public and not current_user.is_authenticated:
        note_refusal("signed_out")
        abort(401)
    if is_public and _USER_ID not in session:
        return
    moment = now()
    if _expired(moment):
        end_session()
        if is_public:
            return
        note_refusal("expired")
        abort(401, SESSION_EXPIRED)
    if is_public:
        return
    if api and not _key_matches():
        note_refusal("session_key")
        abort(401, SESSION_KEY_REFUSED)
    if current_user.must_change_password and not is_allowed_before_password_change(
        current_app.view_functions.get(endpoint)
    ):
        abort(403, PASSWORD_CHANGE_NEEDED, detail={"reason": "password_change_needed"})
    if request.headers.get(BACKGROUND_HEADER) != "1":
        session[SEEN_AT] = _stamp(moment)


def _expired(moment: datetime) -> bool:
    login_at = _read_stamp(session.get(LOGIN_AT))
    seen_at = _read_stamp(session.get(SEEN_AT))
    return (
        login_at is None
        or seen_at is None
        or moment - seen_at >= IDLE_TIMEOUT
        or moment - login_at >= ABSOLUTE_TIMEOUT
        or session.get(SESSION_HOST) != request.host
    )


def _is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _require_json() -> None:
    if request.method not in _WRITE_METHODS or not _is_api(request.path):
        return
    length = request.content_length
    if length is None:
        has_body = "chunked" in request.headers.get("Transfer-Encoding", "").lower()
    else:
        has_body = length > 0
    if has_body and request.mimetype != "application/json":
        abort(415, NOT_JSON)
    if has_body:
        try:
            parsed = request.get_json(silent=True)
        except RecursionError:
            abort(400, JSON_TOO_DEEP)
        if _too_deep(parsed, MAX_JSON_DEPTH):
            abort(400, JSON_TOO_DEEP)


def _too_deep(value: object, limit: int) -> bool:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        children: Iterable[object]
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children if isinstance(child, dict | list))
    return False


def _csrf_failed(_error: CSRFError) -> tuple[dict[str, Any], int]:
    note_refusal("csrf")
    return MessageOut(message=CSRF_FAILED).model_dump(), 400


def _security_headers(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = content_security_policy(g.get("style_nonce"))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if current_app.config.get(SEND_HSTS) and request.is_secure:
        response.headers["Strict-Transport-Security"] = HSTS
    if _is_api(request.path):
        response.headers["Cache-Control"] = "no-store"
    return response
