import os
import sqlite3
from importlib import resources
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import URL, Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from gitmortem.db.compact import CompactRefused, compact

WRITE_TRANSACTION = "gitmortem_write_transaction"
MIN_SQLITE_VERSION = (3, 35)


class UnsupportedSQLite(Exception):
    pass


JOURNAL_SIZE_LIMIT = 64 << 20


def require_supported_sqlite() -> None:
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        minimum = ".".join(str(part) for part in MIN_SQLITE_VERSION)
        raise UnsupportedSQLite(
            f"SQLite {sqlite3.sqlite_version} is too old: GitMortem needs SQLite {minimum} or "
            "newer (the library Python's sqlite3 module uses)"
        )


def make_engine(database_path: Path) -> Engine:
    require_supported_sqlite()
    database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not database_path.exists():
        os.close(os.open(database_path, os.O_CREAT | os.O_WRONLY, 0o600))
    elif os.name == "posix":
        for path in (
            database_path,
            *(database_path.with_name(database_path.name + s) for s in ("-wal", "-shm")),
        ):
            if path.exists() and path.stat().st_mode & 0o077:
                path.chmod(0o600)
    engine = create_engine(URL.create("sqlite", database=str(database_path)), hide_parameters=True)

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA secure_delete=ON")
        cursor.execute(f"PRAGMA journal_size_limit={JOURNAL_SIZE_LIMIT}")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _begin(connection: Any) -> None:
        immediate = connection.get_execution_options().get(WRITE_TRANSACTION, False)
        connection.exec_driver_sql("BEGIN IMMEDIATE" if immediate else "BEGIN")

    return engine


def truncate_journal(engine: Engine) -> bool:
    with engine.connect() as connection:
        raw: Any = connection.connection.dbapi_connection
        busy, _, _ = raw.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    return bool(busy == 0)


def write_engine(engine: Engine) -> Engine:
    return engine.execution_options(**{WRITE_TRANSACTION: True})


FIRST_SEALED_MESSAGES = "0019"


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


def migrations_dir() -> Path:
    return Path(str(resources.files("gitmortem") / "migrations"))


def alembic_config(connection: Any, *, instance_key: bytes | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(migrations_dir()).replace("%", "%%"))
    config.attributes["connection"] = connection
    config.attributes["instance_key"] = instance_key
    return config


def upgrade_database(engine: Engine, *, instance_key: bytes | None = None) -> None:
    with write_engine(engine).connect() as connection:
        before = set(MigrationContext.configure(connection).get_current_heads())
        connection.rollback()
        raw: Any = connection.connection.dbapi_connection
        raw.execute("PRAGMA foreign_keys=OFF")
        try:
            with connection.begin():
                command.upgrade(alembic_config(connection, instance_key=instance_key), "head")
                violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
                if violations:
                    raise RuntimeError(
                        f"migration left {len(violations)} foreign key violation(s); rolled back"
                    )
        finally:
            raw.execute("PRAGMA foreign_keys=ON")
    truncate_journal(engine)
    if before and min(before) < FIRST_SEALED_MESSAGES:
        clear_free_space(engine)


def clear_free_space(engine: Engine) -> None:
    database = engine.url.database
    if not database or database == ":memory:":
        return
    try:
        compact(engine, Path(database).parent)
        return
    except CompactRefused:
        pass
    raw = engine.raw_connection()
    try:
        driver: Any = raw.driver_connection
        driver.execute("PRAGMA temp_store = MEMORY")
        driver.execute("VACUUM")
        driver.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        raw.close()


def schema_is_behind(engine: Engine) -> bool:
    with engine.connect() as connection:
        current = set(MigrationContext.configure(connection).get_current_heads())
    heads = set(ScriptDirectory.from_config(alembic_config(None)).get_heads())
    return current != heads
