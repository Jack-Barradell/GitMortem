from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine


class CompactRefused(Exception):
    pass


def check_temp_folder(engine: Engine, temp_dir: Path) -> None:
    raw = engine.raw_connection()
    try:
        with _copy_kept_in(raw.driver_connection, temp_dir):
            pass
    finally:
        raw.close()


def compact(engine: Engine, temp_dir: Path) -> bool:
    raw = engine.raw_connection()
    try:
        driver: Any = raw.driver_connection
        with _copy_kept_in(driver, temp_dir):
            driver.execute("VACUUM")
            busy, _, _ = driver.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return not busy
    finally:
        raw.close()


@contextmanager
def _copy_kept_in(driver: Any, temp_dir: Path) -> Iterator[None]:
    place = str(temp_dir)
    try:
        place.encode("utf-8")
    except UnicodeEncodeError:
        raise CompactRefused("the data folder's name is not text SQLite can be given") from None
    driver.execute(f"PRAGMA temp_store_directory = '{place.replace(chr(39), chr(39) * 2)}'")
    try:
        row = driver.execute("PRAGMA temp_store_directory").fetchone()
        if row is None or row[0] != place:
            raise CompactRefused(
                "this SQLite cannot keep VACUUM's copy of the database in the data folder"
            )
        yield
    finally:
        driver.execute("PRAGMA temp_store_directory = ''")
