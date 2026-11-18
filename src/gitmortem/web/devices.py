import hashlib
import hmac
from datetime import datetime, timedelta
from typing import cast

from flask import Response, current_app, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from gitmortem.accounts import users
from gitmortem.accounts.users import USERNAME_PATTERN, Device
from gitmortem.db.models import User

DEVICE_LIFETIME = timedelta(days=180)
DEVICE_KEY = "GITMORTEM_DEVICE_KEY"
DEVICE_COOKIE = "GITMORTEM_DEVICE_COOKIE"
COOKIE_PATH = "/api/auth/login"
_SALT = "gitmortem.device"


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        _key(), salt=_SALT, signer_kwargs={"digest_method": hashlib.sha256}
    )


def _key() -> bytes:
    return cast(bytes, current_app.config[DEVICE_KEY])


def cookie_name(username: str) -> str:
    tag = hmac.new(_key(), b"cookie:" + username.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{current_app.config[DEVICE_COOKIE]}_{tag}"


def _claimed(name: str) -> str | None:
    raw = request.cookies.get(cookie_name(name))
    if raw is None:
        return None
    try:
        claim = _serializer().loads(raw, max_age=int(DEVICE_LIFETIME.total_seconds()))
    except BadSignature:
        return None
    if not isinstance(claim, dict):
        return None
    username, device_id = claim.get("u"), claim.get("d")
    if username != name or not isinstance(device_id, str):
        return None
    return device_id


def presented_device(db: Session, typed_username: str) -> Device | None:
    name = typed_username.strip().casefold()
    if not USERNAME_PATTERN.fullmatch(name):
        return None
    device_id = _claimed(name)
    if device_id is None or not users.device_is_live(db, _key(), name, device_id):
        return None
    return Device(username=name, device_id=device_id)


def remembered_device(db: Session, user: User, presented: Device | None, now: datetime) -> str:
    held = presented.device_id if presented is not None else _claimed(user.username)
    return users.remember_device(db, user, _key(), held, now)


def remember_device(response: Response, username: str, device_id: str) -> Response:
    token = _serializer().dumps({"u": username, "d": device_id})
    response.set_cookie(
        cookie_name(username),
        token,
        max_age=int(DEVICE_LIFETIME.total_seconds()),
        path=COOKIE_PATH,
        secure=bool(current_app.config["SESSION_COOKIE_SECURE"]),
        httponly=True,
        samesite="Strict",
    )
    return response
