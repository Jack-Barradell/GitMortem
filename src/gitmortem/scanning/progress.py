from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from gitmortem.crypto import RawStore
from gitmortem.db.models import IntegrityState, Repository, Scan, ToolRun, ToolRunState, User
from gitmortem.triage.context import clean_file_text

MAX_PER_PAGE = 200
MAX_PAGE = 1_000_000_000
OUTPUT_PART = "stderr"
OUTPUT_TAIL_BYTES = 64 << 10


@dataclass(frozen=True)
class ScanSummary:
    scan: Scan
    started_by: str | None
    run_count: int


@dataclass(frozen=True)
class RunRow:
    run: ToolRun
    display_path: str
    has_output: bool


@dataclass(frozen=True)
class RunOutput:
    text: str = field(repr=False)
    size: int
    cut: bool


def started_by(session: Session, scan: Scan) -> str | None:
    if scan.started_by_user_id is None:
        return None
    return session.scalar(select(User.username).where(User.id == scan.started_by_user_id))


def list_scans(session: Session, *, page: int, per_page: int) -> tuple[list[ScanSummary], int]:
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    total = session.scalar(select(func.count()).select_from(Scan)) or 0
    rows = session.execute(
        select(Scan, User.username)
        .outerjoin(User, Scan.started_by_user_id == User.id)
        .order_by(Scan.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()
    ids = [scan.id for scan, _ in rows]
    counts: dict[int, int] = {
        scan_id: count
        for scan_id, count in session.execute(
            select(ToolRun.scan_id, func.count())
            .where(ToolRun.scan_id.in_(ids))
            .group_by(ToolRun.scan_id)
        )
    }
    return [ScanSummary(scan, name, counts.get(scan.id, 0)) for scan, name in rows], total


def run_counts(
    session: Session, scan_id: int
) -> tuple[dict[ToolRunState, int], dict[IntegrityState, int]]:
    states = dict.fromkeys(ToolRunState, 0)
    for state, count in session.execute(
        select(ToolRun.state, func.count())
        .where(ToolRun.scan_id == scan_id)
        .group_by(ToolRun.state)
    ):
        states[state] = count
    integrity = dict.fromkeys(IntegrityState, 0)
    for checked, count in session.execute(
        select(ToolRun.integrity, func.count())
        .where(ToolRun.scan_id == scan_id)
        .group_by(ToolRun.integrity)
    ):
        integrity[checked] = count
    return states, integrity


def scan_runs(
    session: Session, scan_id: int, *, page: int, per_page: int
) -> tuple[list[RunRow], int]:
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, min(page, MAX_PAGE))
    total = (
        session.scalar(select(func.count()).select_from(ToolRun).where(ToolRun.scan_id == scan_id))
        or 0
    )
    parts = aliased(ToolRun)
    rows = session.execute(
        select(ToolRun, Repository.display_path, parts.raw_parts)
        .join(Repository, ToolRun.repository_id == Repository.id)
        .join(parts, parts.id == func.coalesce(ToolRun.parts_run_id, ToolRun.id))
        .where(ToolRun.scan_id == scan_id)
        .order_by(ToolRun.id)
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    return [RunRow(run, path, OUTPUT_PART in sealed) for run, path, sealed in rows], total


def run_output(
    session: Session, raw_store: RawStore, scan_id: int, run_id: int
) -> RunOutput | None:
    parts = aliased(ToolRun)
    found = session.execute(
        select(parts.scan_id, parts.id, parts.raw_parts)
        .select_from(ToolRun)
        .join(parts, parts.id == func.coalesce(ToolRun.parts_run_id, ToolRun.id))
        .where(ToolRun.id == run_id, ToolRun.scan_id == scan_id)
    ).one_or_none()
    if found is None:
        return None
    owner_scan, owner_run, sealed = found
    if OUTPUT_PART not in sealed:
        return RunOutput(text="", size=0, cut=False)
    tail, size = raw_store.read_tail(owner_scan, owner_run, OUTPUT_PART, OUTPUT_TAIL_BYTES)
    cut = size > len(tail)
    if cut:
        _, newline, rest = tail.partition(b"\n")
        tail = rest if newline else tail
    return RunOutput(text=clean_file_text(tail.decode("utf-8", "replace")), size=size, cut=cut)
