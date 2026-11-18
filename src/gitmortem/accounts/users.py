import hashlib
import hmac
import ipaddress
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import and_, case, delete, func, literal, or_, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from gitmortem.accounts.audit import AuditAction, record
from gitmortem.accounts.passwords import (
    burn_verify_time,
    hash_password,
    needs_rehash,
    verify_password,
)
from gitmortem.db.models import LoginThrottle, RememberedDevice, Role, User, UTCDateTime, utcnow

PASSWORD_MIN = 15
PASSWORD_MAX = 128
USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,64}$")
LOCKOUT_THRESHOLD = 5
ADDRESS_LOCKOUT_THRESHOLD = 30
MAX_DEVICES = 10
LOCKOUT_WINDOW = LOCKOUT_DURATION = timedelta(minutes=15)
INVALID_USERNAME = "<invalid>"
UNKNOWN_USERNAME = "<unknown>"


class UserError(Exception):
    pass


class InvalidUsername(UserError):
    pass


class WeakPassword(UserError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DuplicateUsername(UserError):
    pass


class LastAdminError(UserError):
    pass


class UserNotFound(UserError):
    pass


class InvalidCredentials(UserError):
    pass


class AccountLocked(UserError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(f"account locked; retry in {retry_after_seconds} seconds")
        self.retry_after_seconds = retry_after_seconds


class ThrottleScope(StrEnum):
    ACCOUNT = "account"
    ADDRESS = "address"
    DEVICE = "device"
    PASSWORD_CHANGE = "password_change"  # noqa: S105


@dataclass(frozen=True)
class Device:
    username: str
    device_id: str


def normalize_username(raw: str) -> str:
    name = raw.strip().casefold()
    if not USERNAME_PATTERN.fullmatch(name):
        raise InvalidUsername(
            "usernames are 3-64 characters: lowercase letters, digits, '.', '_' and '-'"
        )
    return name


def validate_password(pw: str, *, username: str) -> None:
    if len(pw) < PASSWORD_MIN:
        raise WeakPassword(f"password must be at least {PASSWORD_MIN} characters")
    if len(pw) > PASSWORD_MAX:
        raise WeakPassword(f"password must be at most {PASSWORD_MAX} characters")
    if pw.casefold() == username.strip().casefold():
        raise WeakPassword("password must not be the same as the username")


def count_active_admins(session: Session) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.is_active.is_(True))
        )
        or 0
    )


def get_user(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise UserNotFound(f"no user with id {user_id}")
    return user


def _insert_user(
    session: Session,
    *,
    username: str,
    password: str,
    role: Role,
    pepper: bytes | None,
    must_change: bool = False,
) -> User:
    name = normalize_username(username)
    validate_password(password, username=name)
    user = User(
        username=name,
        password_hash=hash_password(password, pepper),
        role=role,
        must_change_password=must_change,
    )
    try:
        with session.begin_nested():
            session.add(user)
    except IntegrityError:
        raise DuplicateUsername("that username is already taken") from None
    return user


def create_user(
    session: Session,
    *,
    username: str,
    password: str,
    role: Role,
    actor: User | None,
    ip: str | None,
    must_change: bool,
    pepper: bytes | None = None,
) -> User:
    user = _insert_user(
        session,
        username=username,
        password=password,
        role=role,
        pepper=pepper,
        must_change=must_change,
    )
    detail: dict[str, str | int | bool] = {"role": role.value}
    if actor is None:
        detail["via"] = "cli"
    record(session, AuditAction.USER_CREATED, actor=actor, target=user, ip=ip, detail=detail)
    return user


def bootstrap_admin(
    session: Session, *, username: str, password: str, pepper: bytes | None = None
) -> User:
    if count_active_admins(session) != 0:
        raise UserError("an active admin already exists")
    user = _insert_user(
        session, username=username, password=password, role=Role.ADMIN, pepper=pepper
    )
    record(session, AuditAction.ADMIN_BOOTSTRAPPED, actor=None, target=user, detail={"via": "cli"})
    return user


def _is_last_active_admin(session: Session, target: User) -> bool:
    return target.role == Role.ADMIN and target.is_active and count_active_admins(session) <= 1


def device_hmac(device_key: bytes, device_id: str) -> str:
    return hmac.new(device_key, b"device:" + device_id.encode(), hashlib.sha256).hexdigest()


def device_is_live(session: Session, device_key: bytes, username: str, device_id: str) -> bool:
    found = session.scalar(
        select(RememberedDevice.id)
        .join(User, User.id == RememberedDevice.user_id)
        .where(
            RememberedDevice.key_hmac == device_hmac(device_key, device_id),
            User.username == username,
            User.is_active.is_(True),
        )
    )
    return found is not None


def remember_device(
    session: Session, user: User, device_key: bytes, presented: str | None, now: datetime
) -> str:
    if presented is not None:
        held = session.scalar(
            select(RememberedDevice).where(
                RememberedDevice.key_hmac == device_hmac(device_key, presented),
                RememberedDevice.user_id == user.id,
            )
        )
        if held is not None:
            held.last_used_at = now
            return presented
    device_id = secrets.token_urlsafe(16)
    session.add(
        RememberedDevice(
            user_id=user.id,
            key_hmac=device_hmac(device_key, device_id),
            created_at=now,
            last_used_at=now,
        )
    )
    session.flush()
    kept = select(RememberedDevice.id).where(RememberedDevice.user_id == user.id)
    newest = kept.order_by(RememberedDevice.last_used_at.desc(), RememberedDevice.id.desc())
    session.execute(
        delete(RememberedDevice).where(
            RememberedDevice.user_id == user.id,
            RememberedDevice.id.not_in(newest.limit(MAX_DEVICES)),
        )
    )
    return device_id


def forget_devices(session: Session, user: User) -> None:
    session.execute(delete(RememberedDevice).where(RememberedDevice.user_id == user.id))


def throttle_id(throttle_key: bytes, scope: ThrottleScope, value: str) -> str:
    message = f"{scope.value}:{value}".encode()
    return hmac.new(throttle_key, message, hashlib.sha256).hexdigest()


def address_bucket(ip: str | None) -> str:
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(address) >> 64 << 64, 64)))
    return str(address)


def _prune_lapsed(session: Session, now: datetime) -> None:
    session.execute(
        delete(LoginThrottle).where(
            or_(
                and_(
                    LoginThrottle.first_failed_at <= now - LOCKOUT_WINDOW,
                    or_(LoginThrottle.locked_until.is_(None), LoginThrottle.locked_until <= now),
                ),
                LoginThrottle.first_failed_at > now + LOCKOUT_WINDOW,
                LoginThrottle.locked_until > now + 2 * LOCKOUT_DURATION,
            )
        )
    )


def _attempt(
    session: Session, row_id: str, now: datetime, threshold: int = LOCKOUT_THRESHOLD
) -> int:
    table = LoginThrottle.__table__
    insert_stmt = sqlite_insert(LoginThrottle).values(
        key_hmac=row_id, failed_count=1, first_failed_at=now, locked_until=None
    )
    expired = or_(
        table.c.first_failed_at <= now - LOCKOUT_WINDOW,
        table.c.first_failed_at > now + LOCKOUT_WINDOW,
    )
    locked = and_(table.c.locked_until > now, table.c.locked_until <= now + 2 * LOCKOUT_DURATION)
    stmt = insert_stmt.on_conflict_do_update(
        index_elements=[table.c.key_hmac],
        set_={
            "failed_count": case(
                (locked, table.c.failed_count),
                (expired, 1),
                else_=table.c.failed_count + 1,
            ),
            "first_failed_at": case(
                (locked, table.c.first_failed_at),
                (expired, literal(now, UTCDateTime())),
                else_=table.c.first_failed_at,
            ),
            "locked_until": case(
                (locked, table.c.locked_until), (expired, None), else_=table.c.locked_until
            ),
        },
    ).returning(table.c.failed_count, table.c.locked_until)
    count, locked_until = session.execute(stmt).one()
    if locked_until is not None and locked_until > now:
        raise AccountLocked(max(1, math.ceil((locked_until - now).total_seconds())))
    if count > threshold:
        session.execute(
            update(LoginThrottle)
            .where(LoginThrottle.key_hmac == row_id, LoginThrottle.locked_until.is_(None))
            .values(locked_until=now + LOCKOUT_DURATION)
        )
        raise AccountLocked(math.ceil(LOCKOUT_DURATION.total_seconds()))
    return int(count)


def _lock_if_threshold(
    session: Session,
    row_id: str,
    count: int,
    *,
    scope: ThrottleScope,
    target: User | None,
    ip: str | None,
    now: datetime,
    threshold: int = LOCKOUT_THRESHOLD,
) -> None:
    if count != threshold:
        return
    session.execute(
        update(LoginThrottle)
        .where(LoginThrottle.key_hmac == row_id)
        .values(locked_until=now + LOCKOUT_DURATION)
    )
    record(
        session,
        AuditAction.LOGIN_LOCKED,
        actor=None,
        target=target,
        ip=ip,
        detail={"scope": scope.value},
        at=now,
    )


def _retry_after(session: Session, row_id: str, now: datetime) -> int | None:
    locked_until = session.scalar(
        select(LoginThrottle.locked_until).where(LoginThrottle.key_hmac == row_id)
    )
    if locked_until is None or locked_until <= now or locked_until > now + 2 * LOCKOUT_DURATION:
        return None
    return max(1, math.ceil((locked_until - now).total_seconds()))


def _count_address_failure(
    session: Session, row_id: str | None, *, ip: str | None, now: datetime
) -> None:
    if row_id is None:
        return
    count = _attempt(session, row_id, now, ADDRESS_LOCKOUT_THRESHOLD)
    _lock_if_threshold(
        session,
        row_id,
        count,
        scope=ThrottleScope.ADDRESS,
        target=None,
        ip=ip,
        now=now,
        threshold=ADDRESS_LOCKOUT_THRESHOLD,
    )


def _clear_throttle(session: Session, row_id: str) -> None:
    session.execute(delete(LoginThrottle).where(LoginThrottle.key_hmac == row_id))


def authenticate(
    session: Session,
    *,
    username: str,
    password: str,
    ip: str | None,
    now: datetime,
    throttle_key: bytes,
    device: Device | None = None,
    pepper: bytes | None = None,
) -> User:
    _prune_lapsed(session, now)
    name = username.strip().casefold()
    remembered = device if device is not None and device.username == name else None
    address_row = (
        None
        if remembered is not None
        else throttle_id(throttle_key, ThrottleScope.ADDRESS, address_bucket(ip))
    )
    if address_row is not None:
        retry = _retry_after(session, address_row, now)
        if retry is not None:
            raise AccountLocked(retry)

    if not USERNAME_PATTERN.fullmatch(name):
        burn_verify_time(password)
        record(
            session,
            AuditAction.LOGIN_FAILED,
            actor=None,
            ip=ip,
            detail={"username": INVALID_USERNAME},
            at=now,
        )
        _count_address_failure(session, address_row, ip=ip, now=now)
        raise InvalidCredentials("invalid username or password")

    if remembered is not None:
        scope, row_id = (
            ThrottleScope.DEVICE,
            throttle_id(throttle_key, ThrottleScope.DEVICE, remembered.device_id),
        )
    else:
        scope, row_id = (
            ThrottleScope.ACCOUNT,
            throttle_id(throttle_key, ThrottleScope.ACCOUNT, name),
        )
    count = _attempt(session, row_id, now)
    user = session.scalar(select(User).where(User.username == name))
    if user is None or not user.is_active:
        burn_verify_time(password)
        ok = False
    else:
        ok = verify_password(user.password_hash, password, pepper)

    if ok and user is not None:
        _clear_throttle(session, row_id)
        user.last_login_at = now
        if needs_rehash(user.password_hash, pepper):
            user.password_hash = hash_password(password, pepper)
        record(session, AuditAction.LOGIN_SUCCEEDED, actor=user, target=user, ip=ip, at=now)
        return user

    record(
        session,
        AuditAction.LOGIN_FAILED,
        actor=None,
        target=user,
        ip=ip,
        detail={"username": name if user is not None else UNKNOWN_USERNAME},
        at=now,
    )
    _lock_if_threshold(session, row_id, count, scope=scope, target=user, ip=ip, now=now)
    _count_address_failure(session, address_row, ip=ip, now=now)
    raise InvalidCredentials("invalid username or password")


def _verify_current(
    session: Session,
    *,
    user: User,
    password: str,
    ip: str | None,
    throttle_key: bytes,
    now: datetime,
    pepper: bytes | None,
    context: str,
) -> None:
    row_id = throttle_id(throttle_key, ThrottleScope.PASSWORD_CHANGE, str(user.id))
    _prune_lapsed(session, now)
    count = _attempt(session, row_id, now)
    if not verify_password(user.password_hash, password, pepper):
        record(
            session,
            AuditAction.LOGIN_FAILED,
            actor=user,
            target=user,
            ip=ip,
            detail={"context": context},
            at=now,
        )
        _lock_if_threshold(
            session,
            row_id,
            count,
            scope=ThrottleScope.PASSWORD_CHANGE,
            target=user,
            ip=ip,
            now=now,
        )
        raise InvalidCredentials("current password is incorrect")
    _clear_throttle(session, row_id)


def confirm_password(
    session: Session,
    *,
    user: User,
    password: str,
    ip: str | None,
    throttle_key: bytes,
    now: datetime | None = None,
    pepper: bytes | None = None,
) -> None:
    _verify_current(
        session,
        user=user,
        password=password,
        ip=ip,
        throttle_key=throttle_key,
        now=now or utcnow(),
        pepper=pepper,
        context="password_confirm",
    )


def change_password(
    session: Session,
    *,
    user: User,
    current_password: str,
    new_password: str,
    ip: str | None,
    throttle_key: bytes,
    now: datetime | None = None,
    pepper: bytes | None = None,
) -> None:
    when = now or utcnow()
    validate_password(new_password, username=user.username)
    _verify_current(
        session,
        user=user,
        password=current_password,
        ip=ip,
        throttle_key=throttle_key,
        now=when,
        pepper=pepper,
        context="password_change",
    )
    if verify_password(user.password_hash, new_password, pepper):
        raise WeakPassword("the new password must differ from the current one")
    user.password_hash = hash_password(new_password, pepper)
    user.must_change_password = False
    user.session_epoch += 1
    forget_devices(session, user)
    record(session, AuditAction.PASSWORD_CHANGED, actor=user, target=user, ip=ip, at=when)


def sign_out(session: Session, *, user: User, ip: str | None, now: datetime | None = None) -> None:
    user.session_epoch += 1
    record(session, AuditAction.LOGOUT, actor=user, target=user, ip=ip, at=now or utcnow())


def reset_password(
    session: Session,
    *,
    actor: User | None,
    target: User,
    new_password: str,
    ip: str | None,
    throttle_key: bytes | None,
    must_change: bool,
    pepper: bytes | None = None,
    clear_all_lockouts: bool = False,
) -> None:
    validate_password(new_password, username=target.username)
    target.password_hash = hash_password(new_password, pepper)
    target.must_change_password = must_change
    target.session_epoch += 1
    forget_devices(session, target)
    if clear_all_lockouts:
        session.execute(delete(LoginThrottle))
        cleared = "all"
    elif throttle_key is not None:
        _clear_throttle(session, throttle_id(throttle_key, ThrottleScope.ACCOUNT, target.username))
        _clear_throttle(
            session, throttle_id(throttle_key, ThrottleScope.PASSWORD_CHANGE, str(target.id))
        )
        cleared = "account"
    else:
        cleared = "none"
    detail: dict[str, str | int | bool] = {"lockouts_cleared": cleared}
    if actor is None:
        detail["via"] = "cli"
    record(session, AuditAction.PASSWORD_RESET, actor=actor, target=target, ip=ip, detail=detail)


def set_role(session: Session, *, actor: User, target: User, role: Role, ip: str | None) -> None:
    if target.role == role:
        return
    if role != Role.ADMIN and _is_last_active_admin(session, target):
        raise LastAdminError("this would leave no active admin")
    previous = target.role
    target.role = role
    record(
        session,
        AuditAction.USER_ROLE_CHANGED,
        actor=actor,
        target=target,
        ip=ip,
        detail={"from": previous.value, "to": role.value},
    )


def set_active(
    session: Session, *, actor: User, target: User, active: bool, ip: str | None
) -> None:
    if target.is_active == active:
        return
    if not active:
        if _is_last_active_admin(session, target):
            raise LastAdminError("this would leave no active admin")
        target.session_epoch += 1
        forget_devices(session, target)
    target.is_active = active
    action = AuditAction.USER_ACTIVATED if active else AuditAction.USER_DEACTIVATED
    record(session, action, actor=actor, target=target, ip=ip)
