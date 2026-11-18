from sqlalchemy import ColumnElement, Exists, Select, exists, select
from sqlalchemy.orm import InstrumentedAttribute

from gitmortem.db.models import DeletionState, Repository, Sighting, ToolRun, ToolRunState

__all__ = [
    "ENDED_RUN",
    "UNFINISHED_RUN",
    "being_deleted",
    "current_sighting",
    "live_sighting",
    "sighted_live",
    "sighted_now",
]

UNFINISHED_RUN = (ToolRunState.QUEUED, ToolRunState.RUNNING)
ENDED_RUN = (
    ToolRunState.DONE,
    ToolRunState.FAILED,
    ToolRunState.TIMED_OUT,
    ToolRunState.CANCELLED,
    ToolRunState.INTERRUPTED,
)


def being_deleted(*, or_deleted: bool = False) -> Select[int]:
    states = (
        (DeletionState.DELETING, DeletionState.DELETED) if or_deleted else (DeletionState.DELETING,)
    )
    return select(Repository.id).where(Repository.deletion_state.in_(states))


def current_sighting() -> Select[int]:
    return (
        select(Sighting.finding_id)
        .join(ToolRun, ToolRun.id == Sighting.tool_run_id)
        .where(ToolRun.superseded_at.is_(None))
    )


def live_sighting() -> Select[int]:
    return current_sighting().where(Sighting.reported_live.is_(True))


def sighted_now(finding_id: ColumnElement[int] | InstrumentedAttribute[int]) -> Exists:
    return exists().where(
        Sighting.finding_id == finding_id,
        ToolRun.id == Sighting.tool_run_id,
        ToolRun.superseded_at.is_(None),
    )


def sighted_live(finding_id: ColumnElement[int] | InstrumentedAttribute[int]) -> Exists:
    return sighted_now(finding_id).where(Sighting.reported_live.is_(True))
