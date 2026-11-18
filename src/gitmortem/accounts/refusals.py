import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from gitmortem.accounts.audit import AuditAction, record
from gitmortem.db.models import User
from gitmortem.scanning.uow import retry_busy

MAX_KEYS = 1_024
FLUSH_KEYS = 100
FLUSH_SECONDS = 60.0
OVERFLOW = "overflow"


@dataclass(frozen=True)
class RefusalKey:
    user_id: int | None
    address: str
    endpoint: str
    reason: str


@dataclass
class Held:
    count: int
    first: datetime
    last: datetime


class RefusalTally:
    def __init__(self, max_keys: int = MAX_KEYS) -> None:
        self._lock = threading.Lock()
        self._held: dict[RefusalKey, Held] = {}
        self._overflow = 0
        self._max_keys = max_keys

    def add(self, key: RefusalKey, at: datetime) -> None:
        with self._lock:
            held = self._held.get(key)
            if held is not None:
                held.count += 1
                held.last = at
            elif len(self._held) < self._max_keys:
                self._held[key] = Held(1, at, at)
            else:
                self._overflow += 1

    def take(self) -> tuple[list[tuple[RefusalKey, Held]], int]:
        with self._lock:
            items = sorted(self._held.items(), key=lambda item: -item[1].count)
            overflow = self._overflow
            self._held = {}
            self._overflow = 0
        return items, overflow

    def put_back(self, items: Sequence[tuple[RefusalKey, Held]], overflow: int) -> None:
        with self._lock:
            self._overflow += overflow
            for key, held in items:
                kept = self._held.get(key)
                if kept is not None:
                    kept.count += held.count
                    kept.first = min(kept.first, held.first)
                elif len(self._held) < self._max_keys:
                    self._held[key] = held
                else:
                    self._overflow += held.count

    def flush(self, engine: Engine) -> int:
        items, overflow = self.take()
        if not items and not overflow:
            return 0
        written = items[:FLUSH_KEYS]
        spilled = overflow + sum(held.count for _, held in items[FLUSH_KEYS:])

        def write(session: Session) -> int:
            users = {
                user.id: user
                for user in session.scalars(
                    select(User).where(
                        User.id.in_({key.user_id for key, _ in written if key.user_id is not None})
                    )
                )
            }
            for key, held in written:
                record(
                    session,
                    AuditAction.ACCESS_REFUSED,
                    actor=None if key.user_id is None else users.get(key.user_id),
                    ip=key.address,
                    detail={
                        "endpoint": key.endpoint,
                        "reason": key.reason,
                        "count": held.count,
                        "first": held.first.isoformat(),
                        "last": held.last.isoformat(),
                    },
                    at=held.last,
                )
            if spilled:
                record(
                    session,
                    AuditAction.ACCESS_REFUSED,
                    actor=None,
                    detail={"reason": OVERFLOW, "count": spilled},
                )
            return len(written) + (1 if spilled else 0)

        try:
            return retry_busy(engine, write)
        except Exception:
            self.put_back(items, overflow)
            raise


class RefusalFlusher:
    def __init__(
        self,
        tally: RefusalTally,
        engine: Engine,
        *,
        every: float = FLUSH_SECONDS,
        report: Callable[[Exception], None] = lambda _exc: None,
    ) -> None:
        self._tally = tally
        self._engine = engine
        self._every = every
        self._report = report
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="refusal-flusher", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _flush(self) -> None:
        try:
            self._tally.flush(self._engine)
        except Exception as exc:
            self._report(exc)

    def _run(self) -> None:
        while not self._stop.wait(self._every):
            self._flush()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()
        self._flush()
