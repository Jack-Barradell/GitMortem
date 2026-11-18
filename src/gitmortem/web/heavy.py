import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext

from apiflask import abort
from flask import Flask, current_app

__all__ = [
    "BUSY",
    "HEAVY_AT_ONCE",
    "HEAVY_WAIT_SECONDS",
    "SPARE_WAIT_SECONDS",
    "heavy_slot",
    "install",
    "slot_if",
    "spare_slot",
]

HEAVY = "gitmortem.heavy"
HEAVY_AT_ONCE = 2
HEAVY_WAIT_SECONDS = 60.0
SPARE_WAIT_SECONDS = 5.0
BUSY = "GitMortem is busy with other large requests: send this one again in a moment."


def install(app: Flask) -> None:
    app.extensions[HEAVY] = threading.BoundedSemaphore(HEAVY_AT_ONCE)


@contextmanager
def heavy_slot() -> Iterator[None]:
    slots: threading.BoundedSemaphore = current_app.extensions[HEAVY]
    if not slots.acquire(timeout=HEAVY_WAIT_SECONDS):
        abort(503, message=BUSY)
    try:
        yield
    finally:
        slots.release()


def slot_if(heavy: bool) -> AbstractContextManager[None]:
    return heavy_slot() if heavy else nullcontext()


@contextmanager
def spare_slot(needed: bool) -> Iterator[bool]:
    if not needed:
        yield True
        return
    slots: threading.BoundedSemaphore = current_app.extensions[HEAVY]
    if not slots.acquire(timeout=SPARE_WAIT_SECONDS):
        yield False
        return
    try:
        yield True
    finally:
        slots.release()
