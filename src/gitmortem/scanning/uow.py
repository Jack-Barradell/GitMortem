import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gitmortem.db import make_session_factory, write_engine

BUSY_ATTEMPTS = 6
BUSY_PAUSE_SECONDS = 0.5
_BUSY = {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


@contextmanager
def unit_of_work(engine: Engine) -> Iterator[Session]:
    with make_session_factory(write_engine(engine))() as session:
        try:
            yield session
        except BaseException:
            session.rollback()
            raise
        session.commit()


@contextmanager
def read_only(engine: Engine) -> Iterator[Session]:
    with make_session_factory(engine)() as session:
        try:
            yield session
        finally:
            session.rollback()


def is_busy(exc: OperationalError) -> bool:
    return getattr(exc.orig, "sqlite_errorcode", None) in _BUSY


def retry_busy[T](engine: Engine, work: Callable[[Session], T]) -> T:
    attempt = 0
    while True:
        try:
            with unit_of_work(engine) as session:
                return work(session)
        except OperationalError as exc:
            attempt += 1
            if attempt >= BUSY_ATTEMPTS or not is_busy(exc):
                raise
            time.sleep(BUSY_PAUSE_SECONDS * attempt)
