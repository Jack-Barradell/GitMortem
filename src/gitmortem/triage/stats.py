from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from gitmortem.triage import query
from gitmortem.triage.query import Filters, Group, ScanScope, View
from gitmortem.triage.subjects import Subject

MAX_GROUPS = 500


class Dimension(StrEnum):
    ORG = "org"
    REPOSITORY = "repository"
    KIND = "kind"
    STATUS = "status"
    TOOL = "tool"


@dataclass(frozen=True)
class Groups:
    groups: list[Group]
    total_groups: int


@dataclass(frozen=True)
class Stats:
    findings: int
    unique: int
    dimensions: dict[Dimension, Groups]


def stats(
    session: Session,
    filters: Filters,
    *,
    view: View,
    only: Collection[Subject] | None = None,
) -> Stats:
    matching = query.matching(filters, view=view, only=only)
    m = matching.c
    findings, unique = query.totals(session, matching)
    columns = {
        Dimension.ORG: (m.org, None),
        Dimension.REPOSITORY: (m.repository_id, m.repo_path),
        Dimension.KIND: (m.kind, None),
        Dimension.STATUS: (m.status, None),
        Dimension.TOOL: (m.tool, None),
    }
    dimensions = {}
    for dimension, (column, label) in columns.items():
        groups, total = query.grouped(session, matching, column, label=label, limit=MAX_GROUPS)
        dimensions[dimension] = Groups(groups=groups, total_groups=total)
    return Stats(findings=findings, unique=unique, dimensions=dimensions)


@dataclass(frozen=True)
class ScanSecrets:
    findings: int
    unique: int
    new_unique: int


def scan_secrets(session: Session, scan_id: int) -> ScanSecrets:
    seen = query.matching(Filters(scan_id=scan_id), view=View.UNIQUE)
    findings, unique = query.totals(session, seen)
    new = query.matching(Filters(scan_id=scan_id, scan_scope=ScanScope.NEW), view=View.UNIQUE)
    _, new_unique = query.totals(session, new)
    return ScanSecrets(findings=findings, unique=unique, new_unique=new_unique)
