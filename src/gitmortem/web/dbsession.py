import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from flask import Flask, Response, current_app, g, got_request_exception, request
from flask.sessions import SecureCookieSessionInterface, SessionMixin
from sqlalchemy import Engine, event
from sqlalchemy.orm import ORMExecuteState, Session, SessionTransaction, sessionmaker

from gitmortem.db import make_session_factory, write_engine

_FACTORY = "gitmortem.db"
_WRITE_FACTORY = "gitmortem.db.write"
_SESSION = "_gitmortem_db"
_FAILED = "_gitmortem_request_failed"
_READING = "_gitmortem_read_phase"
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_WROTE = "gitmortem.wrote"


class _UnitOfWorkSessionInterface(SecureCookieSessionInterface):
    digest_method = staticmethod(hashlib.sha256)

    def save_session(self, app: Flask, session: SessionMixin, response: Response) -> None:
        if g.get(_FAILED):
            return
        super().save_session(app, session, response)


def init_app(app: Flask, engine: Engine) -> None:
    for key, factory in (
        (_FACTORY, make_session_factory(engine)),
        (_WRITE_FACTORY, make_session_factory(write_engine(engine))),
    ):
        event.listen(factory, "after_flush", _note_flush)
        event.listen(factory, "do_orm_execute", _note_statement)
        event.listen(factory, "after_transaction_end", _forget_writes)
        app.extensions[key] = factory
    app.session_interface = _UnitOfWorkSessionInterface()
    app.after_request(_commit)
    got_request_exception.connect(_discard, app)
    app.teardown_appcontext(_close)


def get_db() -> Session:
    if g.get(_READING):
        raise RuntimeError("the request's session is not for use inside a read phase")
    db = g.get(_SESSION)
    if db is None:
        key = _WRITE_FACTORY if request.method in _WRITE_METHODS else _FACTORY
        factory = cast(sessionmaker[Session], current_app.extensions[key])
        db = factory()
        setattr(g, _SESSION, db)
    return cast(Session, db)


def end_read_transaction() -> None:
    db = g.get(_SESSION)
    if db is None:
        return
    if db.new or db.dirty or db.deleted or db.info.get(_WROTE):
        raise RuntimeError("the request has a change that ending its transaction would lose")
    db.rollback()


@contextmanager
def read_phase() -> Iterator[Session]:
    end_read_transaction()
    factory = cast(sessionmaker[Session], current_app.extensions[_FACTORY])
    outer = g.get(_READING, False)
    setattr(g, _READING, True)
    try:
        with factory() as db:
            yield db
    finally:
        setattr(g, _READING, outer)


def _note_flush(session: Session, _flush_context: Any) -> None:
    session.info[_WROTE] = True


def _note_statement(state: ORMExecuteState) -> None:
    if state.is_insert or state.is_update or state.is_delete:
        state.session.info[_WROTE] = True


def _forget_writes(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        session.info.pop(_WROTE, None)


def _commit(response: Response) -> Response:
    db = g.get(_SESSION)
    if db is not None:
        db.commit()
    return response


def _discard(_sender: Any, **_extra: Any) -> None:
    setattr(g, _FAILED, True)
    db = g.pop(_SESSION, None)
    if db is not None:
        db.rollback()
        db.close()


def _close(_exc: BaseException | None) -> None:
    db = g.pop(_SESSION, None)
    if db is not None:
        db.close()
