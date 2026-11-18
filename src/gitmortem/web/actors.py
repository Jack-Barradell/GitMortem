from typing import cast

from flask_login import current_user

from gitmortem.accounts import users
from gitmortem.db.models import Role, User
from gitmortem.web.dbsession import get_db
from gitmortem.web.security import SessionUser


def current_actor() -> User:
    return users.get_user(get_db(), cast(SessionUser, current_user._get_current_object()).id)


def may_end(started_by_user_id: int | None) -> bool:
    actor = cast(SessionUser, current_user._get_current_object())
    return actor.role is Role.ADMIN or (
        started_by_user_id is not None and started_by_user_id == actor.id
    )
