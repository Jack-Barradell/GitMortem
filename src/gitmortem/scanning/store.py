from collections.abc import Collection, Iterable
from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from gitmortem.crypto import Purpose, Sealer
from gitmortem.db.models import (
    Finding,
    KindFrom,
    MetaFrom,
    Secret,
    SecretStatus,
    Sighting,
    ToolRun,
    utcnow,
)
from gitmortem.scanning.tools import ParsedFinding

STANDALONE = ""
KIND_BATCH = 1_000


def _sealed_message(sealer: Sealer, message: str) -> bytes:
    return sealer.seal(message.encode("utf-8"), Purpose.FINDING_MESSAGE)


def _secret_id(
    session: Session,
    sealer: Sealer,
    value: bytes,
    value_hash: str,
    kind: str,
    kind_from: KindFrom,
) -> int:
    found = session.execute(
        select(Secret.id, Secret.kind_from).where(Secret.value_hash == value_hash)
    ).one_or_none()
    if found is not None:
        secret_id, held_from = found
        if held_from is KindFrom.IMPORT and kind_from is KindFrom.SCAN:
            session.execute(
                update(Secret)
                .where(Secret.id == secret_id, Secret.kind_from == KindFrom.IMPORT)
                .values(kind=kind, kind_from=KindFrom.SCAN)
            )
        return secret_id
    session.execute(
        sqlite_insert(Secret)
        .values(
            value_hash=value_hash,
            value_sealed=sealer.seal(value, Purpose.SECRET_VALUE),
            kind=kind,
            kind_from=kind_from,
            created_at=utcnow(),
        )
        .on_conflict_do_nothing()
    )
    return session.scalars(select(Secret.id).where(Secret.value_hash == value_hash)).one()


def _finding_id(
    session: Session,
    sealer: Sealer,
    run: ToolRun,
    finding: ParsedFinding,
    value_hash: str,
    secret_id: int | None,
    first_seen_at: datetime,
) -> int:
    identity = (
        Finding.repository_id == run.repository_id,
        Finding.tool == run.tool,
        Finding.rule == finding.rule,
        Finding.commit == finding.commit,
        Finding.path == finding.path,
        Finding.line == finding.line,
        Finding.value_hash == value_hash,
    )
    found = session.scalar(select(Finding.id).where(*identity))
    if found is not None:
        _refresh(session, sealer, found, finding)
        return found
    session.execute(
        sqlite_insert(Finding)
        .values(
            repository_id=run.repository_id,
            tool=run.tool,
            rule=finding.rule,
            commit=finding.commit,
            path=finding.path,
            display_path=finding.display_path,
            line=finding.line,
            value_hash=value_hash,
            value_sealed=(
                None if finding.value is None else sealer.seal(finding.value, Purpose.FINDING_VALUE)
            ),
            match_sealed=sealer.seal(finding.matched_line, Purpose.FINDING_MATCH),
            secret_id=secret_id,
            author_name=finding.author_name,
            author_email=finding.author_email,
            authored_at=finding.authored_at,
            message_sealed=(
                None
                if finding.commit_message is None
                else _sealed_message(sealer, finding.commit_message)
            ),
            message_cut=finding.message_cut,
            place=finding.place,
            meta_from=finding.meta_from,
            first_seen_at=first_seen_at,
            status=SecretStatus.UNCLASSIFIED if secret_id is None else None,
        )
        .on_conflict_do_nothing()
    )
    return session.scalars(select(Finding.id).where(*identity)).one()


def recompute_imported_kinds(session: Session, secret_ids: Collection[int]) -> None:
    held = sorted(secret_ids)
    if not held:
        return
    first_rule = (
        select(Finding.rule)
        .where(Finding.secret_id == Secret.id)
        .order_by(Finding.id)
        .limit(1)
        .scalar_subquery()
    )
    for start in range(0, len(held), KIND_BATCH):
        session.execute(
            update(Secret)
            .where(
                Secret.id.in_(held[start : start + KIND_BATCH]),
                Secret.kind_from == KindFrom.IMPORT,
            )
            .values(kind=func.coalesce(first_rule, Secret.kind))
            .execution_options(synchronize_session=False)
        )


def _refresh(session: Session, sealer: Sealer, finding_id: int, finding: ParsedFinding) -> None:
    placed = {"display_path": finding.display_path, "place": finding.place}
    if finding.meta_from is MetaFrom.COMMIT:
        session.execute(
            update(Finding)
            .where(Finding.id == finding_id, Finding.meta_from != MetaFrom.COMMIT)
            .values(
                **placed,
                author_name=finding.author_name,
                author_email=finding.author_email,
                authored_at=finding.authored_at,
                message_sealed=(
                    None
                    if finding.commit_message is None
                    else _sealed_message(sealer, finding.commit_message)
                ),
                message_cut=finding.message_cut,
                meta_from=MetaFrom.COMMIT,
            )
        )
    elif finding.meta_from is MetaFrom.NONE:
        session.execute(
            update(Finding)
            .where(Finding.id == finding_id, Finding.meta_from == MetaFrom.REPORT)
            .values(**placed)
        )
    elif finding.commit_message is not None:
        session.execute(
            update(Finding)
            .where(
                Finding.id == finding_id,
                Finding.meta_from == MetaFrom.REPORT,
                Finding.message_sealed.is_(None),
            )
            .values(
                message_sealed=_sealed_message(sealer, finding.commit_message),
                message_cut=finding.message_cut,
            )
        )


def record_results(
    session: Session,
    sealer: Sealer,
    tool_run: ToolRun,
    findings: Iterable[ParsedFinding],
    *,
    first_seen_at: datetime | None = None,
    imported: bool = False,
) -> int:
    seen_at = utcnow() if first_seen_at is None else first_seen_at
    kind_from = KindFrom.IMPORT if imported else KindFrom.SCAN
    seen = 0
    for finding in findings:
        value_hash, secret_id = STANDALONE, None
        if finding.value is not None:
            value_hash = sealer.value_hash(finding.value)
            secret_id = _secret_id(
                session, sealer, finding.value, value_hash, finding.kind or finding.rule, kind_from
            )
        finding_id = _finding_id(session, sealer, tool_run, finding, value_hash, secret_id, seen_at)
        added = session.execute(
            sqlite_insert(Sighting)
            .values(
                finding_id=finding_id, tool_run_id=tool_run.id, reported_live=finding.reported_live
            )
            .on_conflict_do_nothing()
        )
        made = cast(CursorResult[Any], added).rowcount
        if not made and finding.reported_live:
            session.execute(
                update(Sighting)
                .where(Sighting.finding_id == finding_id, Sighting.tool_run_id == tool_run.id)
                .values(reported_live=True)
            )
        seen += made
    tool_run.findings_count += seen
    session.flush()
    return seen
