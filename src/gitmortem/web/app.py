import functools
from collections.abc import Callable
from datetime import datetime
from typing import Any

from apiflask import APIFlask
from flask import Blueprint
from sqlalchemy import Engine

from gitmortem.accounts.refusals import RefusalTally
from gitmortem.config import ConfigError, Mode, Settings
from gitmortem.crypto import Sealer
from gitmortem.db.models import utcnow
from gitmortem.keys import KeyPurpose, derive_subkey
from gitmortem.scanning.service import ScanService
from gitmortem.web import (
    api_audit,
    api_auth,
    api_discoveries,
    api_explorer,
    api_imports,
    api_repositories,
    api_rules,
    api_scan_roots,
    api_scans,
    api_subjects,
    api_tools,
    api_triage,
    api_uploads,
    api_users,
    dbsession,
    devices,
    heavy,
    import_schemas,
    rules_schemas,
    sealing,
    security,
    spa,
)
from gitmortem.web import (
    scans as scans_module,
)
from gitmortem.web.requests import App, IdConverter, id_parameters

BLUEPRINTS: tuple[Blueprint, ...] = (
    spa.bp,
    api_auth.bp,
    api_users.bp,
    api_audit.bp,
    api_scan_roots.bp,
    api_discoveries.bp,
    api_repositories.bp,
    api_scans.bp,
    api_scans.rereads_bp,
    api_tools.bp,
    api_rules.bp,
    api_imports.bp,
    api_uploads.bp,
    api_triage.bp,
    api_subjects.bp,
    api_explorer.bp,
)
SESSION_COOKIE = "gitmortem_session"
DEVICE_COOKIE = "gitmortem_device"
MAX_BODY_BYTES = 1_048_576


def cookie_tag(instance_key: bytes) -> str:
    return derive_subkey(instance_key, KeyPurpose.COOKIE_NAME).hex()[:8]


def session_cookie_name(settings: Settings, instance_key: bytes) -> str:
    name = f"{SESSION_COOKIE}_{cookie_tag(instance_key)}"
    return f"__Host-{name}" if settings.secure_cookies else name


def device_cookie_name(settings: Settings, instance_key: bytes) -> str:
    name = f"{DEVICE_COOKIE}_{cookie_tag(instance_key)}"
    return f"__Secure-{name}" if settings.secure_cookies else name


def create_app(
    settings: Settings,
    *,
    instance_key: bytes,
    engine: Engine,
    clock: Callable[[], datetime] = utcnow,
    scans: ScanService | None = None,
    refusals: RefusalTally | None = None,
) -> APIFlask:
    if not settings.allowed_hosts:
        raise ConfigError("at least one allowed host is required")

    app = App(
        __name__,
        docs_path=None,
        spec_path=None,
        static_folder=None,  # type: ignore[arg-type]
    )
    app.config.update(
        SECRET_KEY=derive_subkey(instance_key, KeyPurpose.SESSION),
        TRUSTED_HOSTS=list(settings.allowed_hosts),
        DEBUG=False,
        SESSION_COOKIE_NAME=session_cookie_name(settings, instance_key),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.secure_cookies,
        PERMANENT_SESSION_LIFETIME=security.ABSOLUTE_TIMEOUT,
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
        WTF_CSRF_TIME_LIMIT=None,
        WTF_CSRF_SSL_STRICT=False,
    )
    app.config[security.THROTTLE_KEY] = derive_subkey(instance_key, KeyPurpose.THROTTLE)
    app.config[security.PASSWORD_PEPPER] = derive_subkey(instance_key, KeyPurpose.PASSWORD)
    app.config[security.SEND_HSTS] = settings.mode is Mode.SERVER and settings.secure_cookies
    app.config[security.TRUSTED_PROXY] = settings.proxy_peer
    app.config[devices.DEVICE_KEY] = derive_subkey(instance_key, KeyPurpose.DEVICE)
    app.config[devices.DEVICE_COOKIE] = device_cookie_name(settings, instance_key)
    app.config[security.SESSION_KEY_MAC] = derive_subkey(instance_key, KeyPurpose.SESSION_KEY)
    app.extensions[spa.STATIC_DIR] = settings.static_dir
    app.extensions[api_scan_roots.SETTINGS] = settings
    app.extensions[sealing.SEALER] = Sealer(instance_key)
    app.extensions[scans_module.SCANS] = scans

    app.url_map.converters["id"] = IdConverter
    heavy.install(app)
    dbsession.init_app(app, engine)
    security.install_guard(app, clock)
    security.install_json_only(app)
    security.install_csrf(app)
    security.install_headers(app)
    security.install_refusal_count(app, RefusalTally() if refusals is None else refusals)

    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)
    security.refuse_unclassified(app)
    app.spec_processor(functools.partial(_described, app))
    return app


def _described(app: APIFlask, spec: dict[Any, Any] | str) -> dict[Any, Any] | str:
    described = import_schemas.add_refusal_schemas(rules_schemas.add_refusal_schemas(spec))
    return id_parameters(app, described) if isinstance(described, dict) else described
