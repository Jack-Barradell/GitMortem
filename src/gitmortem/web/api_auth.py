from typing import NoReturn, cast

from apiflask import APIBlueprint, abort
from flask import Response, after_this_request
from flask_login import current_user
from flask_wtf.csrf import generate_csrf

from gitmortem.accounts import users
from gitmortem.db.models import Role, User
from gitmortem.web.dbsession import get_db
from gitmortem.web.devices import presented_device, remember_device, remembered_device
from gitmortem.web.schemas import (
    CsrfOut,
    LoginIn,
    LoginOut,
    MeOut,
    PasswordChangeIn,
    PasswordConfirmIn,
    SessionKeyOut,
)
from gitmortem.web.security import (
    IDLE_TIMEOUT,
    SessionUser,
    allowed_before_password_change,
    client_ip,
    end_session,
    mark_reauthenticated,
    now,
    password_pepper,
    public,
    require_role,
    start_session,
    throttle_key,
)

INVALID_CREDENTIALS = "Invalid username or password."
TOO_MANY_ATTEMPTS = "Too many failed attempts. Try again later."
WRONG_CURRENT_PASSWORD = "Current password is incorrect."  # noqa: S105
WRONG_PASSWORD = "That password is incorrect."  # noqa: S105

bp = APIBlueprint("auth", __name__, url_prefix="/api/auth")


@bp.get("/csrf")
@public
@bp.output(CsrfOut)
def csrf() -> CsrfOut:
    return CsrfOut(csrf_token=generate_csrf())


@bp.post("/login")
@public
@bp.input(LoginIn, arg_name="credentials")
@bp.output(LoginOut)
@bp.doc(responses={401: INVALID_CREDENTIALS, 429: TOO_MANY_ATTEMPTS})
def login(credentials: LoginIn) -> LoginOut:
    moment = now()
    try:
        user = users.authenticate(
            get_db(),
            username=credentials.username,
            password=credentials.password,
            ip=client_ip(),
            now=moment,
            throttle_key=throttle_key(),
            device=presented_device(get_db(), credentials.username),
            pepper=password_pepper(),
        )
    except users.AccountLocked as locked:
        _too_many_attempts(locked)
    except users.InvalidCredentials:
        abort(401, INVALID_CREDENTIALS)
    key = start_session(user, moment)
    device_id = remembered_device(get_db(), user, None, moment)

    @after_this_request
    def _remember(response: Response) -> Response:
        return remember_device(response, user.username, device_id)

    shown = _me(user)
    return LoginOut(**shown.model_dump(), session_key=key)


@bp.post("/logout")
@require_role(Role.ANALYST)
@allowed_before_password_change
@bp.doc(responses={204: "Signed out; every session of this user has ended"})
def logout() -> tuple[str, int]:
    db = get_db()
    user = users.get_user(db, _session_user().id)
    users.sign_out(db, user=user, ip=client_ip(), now=now())
    end_session()
    return "", 204


@bp.get("/me")
@require_role(Role.ANALYST)
@allowed_before_password_change
@bp.output(MeOut)
def me() -> MeOut:
    return _me(_session_user())


@bp.post("/password")
@require_role(Role.ANALYST)
@allowed_before_password_change
@bp.input(PasswordChangeIn, arg_name="change")
@bp.output(SessionKeyOut, description="Password changed; the user's other sessions are signed out")
@bp.doc(responses={400: WRONG_CURRENT_PASSWORD, 429: TOO_MANY_ATTEMPTS})
def password(change: PasswordChangeIn) -> SessionKeyOut:
    db = get_db()
    user = users.get_user(db, _session_user().id)
    moment = now()
    try:
        users.change_password(
            db,
            user=user,
            current_password=change.current_password,
            new_password=change.new_password,
            ip=client_ip(),
            now=moment,
            throttle_key=throttle_key(),
            pepper=password_pepper(),
        )
    except users.AccountLocked as locked:
        _too_many_attempts(locked)
    except users.InvalidCredentials:
        abort(400, WRONG_CURRENT_PASSWORD)
    except users.WeakPassword as weak:
        abort(422, weak.reason)
    return SessionKeyOut(session_key=start_session(user, moment))


@bp.post("/confirm")
@require_role(Role.ANALYST)
@bp.input(PasswordConfirmIn, arg_name="given")
@bp.doc(
    responses={
        204: "Confirmed: for the next ten minutes no admin action asks again",
        400: WRONG_PASSWORD,
        429: TOO_MANY_ATTEMPTS,
    }
)
def confirm(given: PasswordConfirmIn) -> tuple[str, int]:
    db = get_db()
    user = users.get_user(db, _session_user().id)
    moment = now()
    try:
        users.confirm_password(
            db,
            user=user,
            password=given.password,
            ip=client_ip(),
            now=moment,
            throttle_key=throttle_key(),
            pepper=password_pepper(),
        )
    except users.AccountLocked as locked:
        _too_many_attempts(locked)
    except users.InvalidCredentials:
        abort(400, WRONG_PASSWORD)
    mark_reauthenticated(moment)
    return "", 204


def _too_many_attempts(locked: users.AccountLocked) -> NoReturn:
    abort(429, TOO_MANY_ATTEMPTS, headers={"Retry-After": str(locked.retry_after_seconds)})


def _session_user() -> SessionUser:
    return cast(SessionUser, current_user._get_current_object())


def _me(user: User | SessionUser) -> MeOut:
    return MeOut(
        id=user.id,
        username=user.username,
        role=user.role,
        idle_timeout_seconds=int(IDLE_TIMEOUT.total_seconds()),
        must_change_password=user.must_change_password,
    )
