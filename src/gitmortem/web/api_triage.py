import dataclasses
from enum import StrEnum
from typing import NoReturn

from apiflask import APIBlueprint, abort
from flask import Response

from gitmortem.accounts import audit
from gitmortem.accounts.audit import AuditAction
from gitmortem.db.models import Role
from gitmortem.export import build
from gitmortem.triage import classify, stats, values
from gitmortem.triage.query import (
    Group,
    ListPage,
    ListSort,
    Row,
    choices,
    facets,
    list_page,
    matching_subjects,
    path_choices,
)
from gitmortem.triage.subjects import NoSuchSubject, Subject
from gitmortem.web.actors import current_actor
from gitmortem.web.canary_check import possible_canaries
from gitmortem.web.dbsession import get_db, read_phase
from gitmortem.web.heavy import heavy_slot, slot_if
from gitmortem.web.sealing import app_sealer
from gitmortem.web.security import check_role, client_ip, now, require_role
from gitmortem.web.triage_schemas import (
    BoundOut,
    CanariesIn,
    CanariesOut,
    CanarySubjectOut,
    ChoiceOut,
    ChoicesIn,
    ChoicesOut,
    ExportIn,
    FacetScanOut,
    FacetsOut,
    GroupOut,
    GroupsOut,
    ListOut,
    ListQueryIn,
    MatchingTarget,
    PathChoiceOut,
    PathsIn,
    PathsOut,
    ReportedMarkOut,
    RowOut,
    SkippedOut,
    StatsIn,
    StatsOut,
    StatusIn,
    StatusOut,
    ValueOut,
    ValuesIn,
    ValuesOut,
    choice_filters,
)

bp = APIBlueprint("triage", __name__, url_prefix="/api/triage")
NO_SUCH_SUBJECT = "No such secret or finding."
VALUES_ROLE = Role.ANALYST
MAX_SKIPPED = 1_000


@bp.post("/query", endpoint="query")
@require_role(VALUES_ROLE)
@bp.input(ListQueryIn, arg_name="body")
@bp.output(ListOut)
@bp.doc(
    responses={
        403: "A user who may not see values; nothing was read",
        422: "An unknown field, a filter or value search out of its bounds, a sort by value "
        "under the All view, or more values, or bytes of values, to open than one request may",
    }
)
def query_list(body: ListQueryIn) -> ListOut:
    filters = body.filters.filters()
    search = None if body.value_search is None else body.value_search.search()
    sealer = app_sealer()
    matches: frozenset[Subject] | None = None
    heavy = search is not None or body.sort is ListSort.VALUE or filters.searches_sealed
    try:
        with read_phase() as db, slot_if(heavy):
            opened = values.Opened()
            filters = values.search_messages(db, sealer, filters, opened=opened)
            if search is not None:
                matches = values.search(db, sealer, search, opened=opened)
            if body.sort is ListSort.VALUE:
                page = values.value_page(
                    db,
                    sealer,
                    filters,
                    order=body.order,
                    page=body.page,
                    per_page=body.per_page,
                    only=matches,
                    opened=opened,
                    summary=body.summary,
                )
            else:
                page = list_page(
                    db,
                    filters,
                    view=body.view,
                    sort=body.sort,
                    order=body.order,
                    page=body.page,
                    per_page=body.per_page,
                    only=matches,
                    summary=body.summary,
                )
            subjects = list(dict.fromkeys(row.subject for row in page.rows))
            shown = values.values_of(db, sealer, subjects, opened=opened)
    except values.TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    return _list_out(body, page, shown)


@bp.post("/canaries", endpoint="canaries")
@require_role(Role.ANALYST)
@bp.input(CanariesIn, arg_name="body")
@bp.output(CanariesOut)
@bp.doc(responses={422: "An unknown field, or no subject or more than one page of them"})
def list_canaries(body: CanariesIn) -> CanariesOut:
    asked = list(dict.fromkeys(each.subject() for each in body.subjects))
    with read_phase() as db:
        possible, unchecked = possible_canaries(db, app_sealer(), asked, values.Opened())
    return CanariesOut(
        possible=[
            CanarySubjectOut(kind=subject.kind, id=subject.id)
            for subject in asked
            if subject in possible
        ],
        unchecked=unchecked,
    )


def _group_out(group: Group) -> GroupOut:
    key = group.key.value if isinstance(group.key, StrEnum) else group.key
    return GroupOut(key=key, label=group.label, findings=group.findings, unique=group.unique)


def _groups_out(groups: stats.Groups) -> GroupsOut:
    return GroupsOut(
        groups=[_group_out(group) for group in groups.groups], total_groups=groups.total_groups
    )


@bp.post("/stats", endpoint="stats")
@require_role(Role.ANALYST)
@bp.input(StatsIn, arg_name="body")
@bp.output(StatsOut)
@bp.doc(
    responses={
        403: "A value search or a text search by a user who may not see values; nothing was read",
        422: "An unknown field or a filter out of its bounds, or more values to search than "
        "one request may open",
    }
)
def list_stats(body: StatsIn) -> StatsOut:
    if body.value_search is not None or body.filters.text:
        check_role(VALUES_ROLE)
    filters = body.filters.filters()
    try:
        with read_phase() as db, slot_if(body.value_search is not None or filters.searches_sealed):
            sealer = app_sealer()
            opened = values.Opened()
            filters = values.search_messages(db, sealer, filters, opened=opened)
            matches: frozenset[Subject] | None = None
            if body.value_search is not None:
                search = body.value_search.search()
                matches = values.search(db, sealer, search, opened=opened)
            found = stats.stats(db, filters, view=body.view, only=matches)
    except values.TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    dimension = stats.Dimension
    return StatsOut(
        findings=found.findings,
        unique=found.unique,
        by_org=_groups_out(found.dimensions[dimension.ORG]),
        by_repository=_groups_out(found.dimensions[dimension.REPOSITORY]),
        by_kind=_groups_out(found.dimensions[dimension.KIND]),
        by_status=_groups_out(found.dimensions[dimension.STATUS]),
        by_tool=_groups_out(found.dimensions[dimension.TOOL]),
    )


@bp.post("/export", endpoint="export")
@require_role(VALUES_ROLE)
@bp.input(ExportIn, arg_name="body")
@bp.doc(
    responses={
        200: "The file, as an attachment: txt, json, csv or xlsx",
        403: "A user who may not see values; nothing was read or written",
        422: "An unknown field or a filter out of its bounds, a value sort outside the unique "
        "view, or more values, or bytes of values, than one export may take; no file was sent "
        "or audited",
    }
)
def export_list(body: ExportIn) -> Response:
    filters = body.filters.filters()
    chosen = choice_filters(body.filters)
    texted = bool(body.filters.text)
    sealer = app_sealer()
    try:
        with read_phase() as db, heavy_slot():
            filters = values.search_messages(db, sealer, filters)
            matches: frozenset[Subject] | None = None
            if body.value_search is not None:
                search = body.value_search.search()
                matches = values.search(db, sealer, search, opened=values.Opened())
            made = build.build_export(
                db,
                sealer,
                build.ExportRequest(
                    filters=filters,
                    view=body.view,
                    sort=body.sort,
                    order=body.order,
                    only=matches,
                    format=body.format,
                    include_values=body.include_values,
                    text_filtered=texted,
                ),
                now=now(),
            )
    except values.TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    audit.record_carried(
        get_db(),
        AuditAction.SECRETS_EXPORTED,
        actor=current_actor(),
        ip=client_ip(),
        subjects=made.subjects if body.include_values else [],
        detail={
            "format": body.format.value,
            "view": body.view.value,
            "include_values": body.include_values,
            "rows": made.rows,
            "text_filtered": texted,
            "value_searched": matches is not None,
            "filters": chosen,
        },
        filters=chosen,
    )
    return Response(
        made.content,
        content_type=made.media_type,
        headers={"Content-Disposition": f'attachment; filename="{made.filename}"'},
    )


def _list_out(body: ListQueryIn, page: ListPage, shown: dict[Subject, str]) -> ListOut:
    return ListOut(
        items=[_row_out(row, shown[row.subject]) for row in page.rows],
        page=body.page,
        per_page=body.per_page,
        total_findings=page.total_findings,
        total_unique=page.total_unique,
        by_status=None if page.by_status is None else [_group_out(g) for g in page.by_status],
        by_tool=None if page.by_tool is None else [_group_out(g) for g in page.by_tool],
        bound=BoundOut(
            max_secret_id=page.bound.max_secret_id,
            max_finding_id=page.bound.max_finding_id,
            scan_ended=page.bound.scan_ended,
            reported_mark=(
                None
                if (mark := page.bound.reported_mark) is None
                else ReportedMarkOut(**dataclasses.asdict(mark))
            ),
        ),
        last_change_id=page.last_change_id,
    )


@bp.post("/values", endpoint="values")
@require_role(VALUES_ROLE)
@bp.input(ValuesIn, arg_name="body")
@bp.output(ValuesOut)
@bp.doc(
    responses={
        404: "A subject that is not there, or a finding that has a secret; nothing was sent",
        422: "No subject, one named twice, both chosen subjects and select all matching or "
        "neither, an unknown field, select all matching on a scan that has not ended or once "
        "what is reported has moved since its page, or more values, or bytes of values, than "
        "one request may carry",
    }
)
def subject_values(body: ValuesIn) -> ValuesOut:
    sealer = app_sealer()
    matching = body.matching
    if matching is not None:
        filters, bound = matching.filters.filters(), matching.bound.bound()
        try:
            classify.refuse_unended_scan(get_db(), filters, bound)
            classify.refuse_moved_report(get_db(), filters, bound)
        except classify.ScanNotEnded as refused:
            abort(422, message=str(refused))
        except classify.ReportedMoved as refused:
            _reported_moved(refused)
    subjects: list[Subject] = []
    try:
        with read_phase() as db, slot_if(matching is not None):
            opened = values.Opened()
            if matching is None:
                subjects = [each.subject() for each in body.subjects or ()]
            else:
                filters = values.search_messages(db, sealer, filters, opened=opened)
                matches: frozenset[Subject] | None = None
                if matching.value_search is not None:
                    search = matching.value_search.search()
                    matches = values.search(db, sealer, search, opened=opened)
                subjects = matching_subjects(
                    db, filters, view=matching.view, bound=bound, only=matches
                )
            found = values.values_of(db, sealer, subjects, opened=opened)
    except NoSuchSubject:
        abort(404, message=NO_SUCH_SUBJECT)
    except values.TooManyToDecrypt as refused:
        abort(422, message=str(refused))
    return ValuesOut(items=[ValueOut(kind=s.kind, id=s.id, value=found[s]) for s in subjects])


def _reported_moved(refused: classify.ReportedMoved) -> NoReturn:
    abort(422, message=str(refused), detail={"reason": refused.REASON})


@bp.post("/status", endpoint="status")
@require_role(Role.ANALYST)
@bp.input(StatusIn, arg_name="body")
@bp.output(StatusOut)
@bp.doc(
    responses={
        403: "A value search or a text search by a user who may not see values; nothing was "
        "read or written",
        404: "A subject that is not there, or a finding that has a secret; nothing was written",
        409: "A secret the change moves was found in more repositories than "
        "`across_repositories` confirms (`detail.reason` `spans_repositories`, "
        "`detail.repositories` the count); nothing was written",
        422: "An unknown field, a target, status or note out of its bounds, more subjects than "
        "one change may touch, a note too large to copy onto them all, select all matching on a "
        "scan that has not ended, or under a `reported` or `reported_live` filter once what is "
        "reported has moved since its page (`detail.reason` `reported_moved`), or more values to "
        "search than one request may open",
    }
)
def change_status(body: StatusIn) -> StatusOut:
    target = body.target
    sealer = app_sealer()
    matches: frozenset[Subject] | None = None
    matching = target if isinstance(target, MatchingTarget) else None
    if matching is not None and (matching.value_search is not None or matching.filters.text):
        check_role(VALUES_ROLE)
    if matching is not None:
        try:
            classify.refuse_unended_scan(
                get_db(), matching.filters.filters(), matching.bound.bound()
            )
            classify.refuse_moved_report(
                get_db(), matching.filters.filters(), matching.bound.bound()
            )
        except classify.ScanNotEnded as refused:
            abort(422, message=str(refused))
        except classify.ReportedMoved as refused:
            _reported_moved(refused)
    db = get_db()
    if isinstance(target, MatchingTarget):
        searched = target.filters.filters()
        if target.value_search is not None or searched.searches_sealed:
            try:
                with read_phase() as reading, heavy_slot():
                    opened = values.Opened()
                    searched = values.search_messages(reading, sealer, searched, opened=opened)
                    if target.value_search is not None:
                        matches = values.search(
                            reading, sealer, target.value_search.search(), opened=opened
                        )
            except values.TooManyToDecrypt as refused:
                abort(422, message=str(refused))
            db = get_db()
        try:
            subjects = classify.matching_as_seen(
                db,
                searched,
                view=target.view,
                bound=target.bound.bound(),
                only=matches,
                seen_change_id=body.seen_change_id,
            )
        except classify.ScanNotEnded as refused:
            abort(422, message=str(refused))
        except classify.ReportedMoved as refused:
            _reported_moved(refused)
    else:
        subjects = [each.subject() for each in target.subjects]
    try:
        result = classify.set_status(
            db,
            subjects,
            body.status,
            user=current_actor(),
            seen_change_id=body.seen_change_id,
            note=body.note,
            sealer=sealer,
            now=now(),
            across_repositories=body.across_repositories,
            own_batches=body.own_batches,
        )
    except NoSuchSubject:
        db.rollback()
        abort(404, message=NO_SUCH_SUBJECT)
    except (classify.TooManySubjects, classify.NoteTooLarge) as refused:
        abort(422, message=str(refused))
    except classify.SpansRepositories as refused:
        db.rollback()
        abort(
            409,
            message=str(refused),
            detail={"reason": refused.REASON, "repositories": refused.repositories},
        )
    return StatusOut(
        batch_id=result.batch_id,
        changed=result.changed,
        unchanged=result.unchanged,
        skipped=[
            SkippedOut(
                kind=each.subject.kind,
                id=each.subject.id,
                status=each.status,
                changed_by=each.changed_by,
                changed_at=each.changed_at,
            )
            for each in result.skipped[:MAX_SKIPPED]
        ],
        skipped_total=len(result.skipped),
    )


@bp.post("/paths", endpoint="paths")
@require_role(Role.ANALYST)
@bp.input(PathsIn, arg_name="body")
@bp.output(PathsOut)
@bp.doc(responses={422: "An unknown field, or more repositories or text than allowed"})
def list_paths(body: PathsIn) -> PathsOut:
    with read_phase() as db:
        found = path_choices(db, body.repository_ids, body.text)
    return PathsOut(
        items=[
            PathChoiceOut(path=each.path, findings=each.findings, unique=each.unique)
            for each in found
        ]
    )


@bp.post("/choices", endpoint="choices")
@require_role(Role.ANALYST)
@bp.input(ChoicesIn, arg_name="body")
@bp.output(ChoicesOut)
@bp.doc(responses={422: "An unknown field or dimension, too much text, or ids for an org or type"})
def list_choices(body: ChoicesIn) -> ChoicesOut:
    with read_phase() as db:
        found = choices(db, body.dimension, body.text, ids=body.ids)
    return ChoicesOut(
        items=[
            ChoiceOut(
                value=each.value, label=each.label, findings=each.findings, unique=each.unique
            )
            for each in found
        ]
    )


@bp.get("/facets", endpoint="facets")
@require_role(Role.ANALYST)
@bp.output(FacetsOut)
def list_facets() -> FacetsOut:
    found = facets(get_db())
    return FacetsOut(
        tools=found.tools,
        scans=[
            FacetScanOut(id=scan_id, created_at=created_at, state=state)
            for scan_id, created_at, state in found.scans
        ],
    )


def _row_out(row: Row, value: str) -> RowOut:
    return RowOut(
        kind=row.subject.kind,
        id=row.subject.id,
        anchor_finding_id=row.anchor_finding_id,
        repository_id=row.repository_id,
        org=row.org,
        repo_name=row.repo_name,
        display_path=row.display_path,
        commit=row.commit,
        authored_at=row.authored_at,
        kind_label=row.kind,
        tools=list(row.tools),
        status=row.status,
        findings=row.findings,
        repos=row.repos,
        no_longer_reported=row.no_longer_reported,
        reported_live=row.reported_live,
        repository_on_disk=row.repository_on_disk,
        value=value,
    )
