from typing import NoReturn

from apiflask import APIBlueprint, abort
from sqlalchemy import select

from gitmortem.accounts import users
from gitmortem.db.models import Role, User
from gitmortem.web.actors import current_actor
from gitmortem.web.dbsession import get_db
from gitmortem.web.schemas import (
    PasswordResetIn,
    UserCreateIn,
    UserListOut,
    UserOut,
    UserUpdateIn,
)
from gitmortem.web.security import (
    client_ip,
    mark_reauthenticated,
    now,
    password_pepper,
    require_recent_password,
    require_role,
    throttle_key,
)

LAST_ADMIN = "At least one active admin must remain."
DUPLICATE_USERNAME = "That username is already taken."
NO_SUCH_USER = "No such user."
WRONG_CURRENT_PASSWORD = "Your current password is incorrect."  # noqa: S105
TOO_MANY_ATTEMPTS = "Too many failed attempts. Try again later."

bp = APIBlueprint("users", __name__, url_prefix="/api/users")
USER_ID = "<id:user_id>"


@bp.get("", endpoint="list")
@require_role(Role.ADMIN)
@bp.output(UserListOut)
def list_users() -> UserListOut:
    return UserListOut(
        [_out(user) for user in get_db().scalars(select(User).order_by(User.username))]
    )


@bp.post("", endpoint="create")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(UserCreateIn, arg_name="new")
@bp.output(UserOut, status_code=201)
@bp.doc(responses={409: DUPLICATE_USERNAME, 422: "Invalid username or password"})
def create(new: UserCreateIn) -> tuple[UserOut, int]:
    db = get_db()
    try:
        user = users.create_user(
            db,
            username=new.username,
            password=new.password,
            role=new.role,
            actor=current_actor(),
            ip=client_ip(),
            must_change=True,
            pepper=password_pepper(),
        )
    except users.UserError as error:
        _error_response(error)
    return _out(user), 201


@bp.patch(f"/{USER_ID}", endpoint="update")
@require_role(Role.ADMIN)
@require_recent_password
@bp.input(UserUpdateIn, arg_name="change")
@bp.output(UserOut)
@bp.doc(responses={404: NO_SUCH_USER, 409: LAST_ADMIN})
def update(user_id: int, change: UserUpdateIn) -> UserOut:
    db = get_db()
    try:
        target = users.get_user(db, user_id)
        actor = current_actor()
        if change.role is not None:
            users.set_role(db, actor=actor, target=target, role=change.role, ip=client_ip())
        if change.is_active is not None:
            users.set_active(
                db, actor=actor, target=target, active=change.is_active, ip=client_ip()
            )
    except users.UserError as error:
        _error_response(error)
    return _out(target)


@bp.post(f"/{USER_ID}/password", endpoint="reset_password")
@require_role(Role.ADMIN)
@bp.input(PasswordResetIn, arg_name="reset")
@bp.doc(
    responses={
        204: "Password reset; the user's sessions are signed out",
        400: WRONG_CURRENT_PASSWORD,
        404: NO_SUCH_USER,
        422: "Invalid password",
        429: TOO_MANY_ATTEMPTS,
    }
)
def reset_password(user_id: int, reset: PasswordResetIn) -> tuple[str, int]:
    db = get_db()
    actor = current_actor()
    moment = now()
    try:
        target = users.get_user(db, user_id)
        users.validate_password(reset.new_password, username=target.username)
    except users.UserError as error:
        _error_response(error)
    try:
        users.confirm_password(
            db,
            user=actor,
            password=reset.current_password,
            ip=client_ip(),
            now=moment,
            throttle_key=throttle_key(),
            pepper=password_pepper(),
        )
    except users.AccountLocked as locked:
        abort(429, TOO_MANY_ATTEMPTS, headers={"Retry-After": str(locked.retry_after_seconds)})
    except users.InvalidCredentials:
        abort(400, WRONG_CURRENT_PASSWORD)
    mark_reauthenticated(moment)
    try:
        users.reset_password(
            db,
            actor=actor,
            target=target,
            new_password=reset.new_password,
            ip=client_ip(),
            throttle_key=throttle_key(),
            must_change=target.id != actor.id,
            pepper=password_pepper(),
        )
    except users.UserError as error:
        _error_response(error)
    return "", 204


def _error_response(error: users.UserError) -> NoReturn:
    get_db().rollback()
    match error:
        case users.UserNotFound():
            abort(404, NO_SUCH_USER)
        case users.LastAdminError():
            abort(409, LAST_ADMIN)
        case users.DuplicateUsername():
            abort(409, DUPLICATE_USERNAME)
        case users.WeakPassword():
            abort(422, error.reason)
        case users.InvalidUsername():
            abort(422, str(error))
        case _:
            raise error


def _out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
