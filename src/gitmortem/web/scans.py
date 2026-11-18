from typing import NoReturn, cast

from apiflask import abort
from flask import current_app

from gitmortem.scanning.service import Refusal, ScanRefused, ScanService
from gitmortem.web.dbsession import get_db

SCANS = "gitmortem.scans"
NOT_RUNNING = "scanning is not running"
REFUSAL_STATUS: dict[Refusal, int] = {
    Refusal.NO_SUCH_ROOT: 404,
    Refusal.DISCOVERY_RUNNING: 409,
    Refusal.NO_SUCH_SCAN: 404,
    Refusal.SCAN_UNFINISHED: 409,
}


def running_scans() -> ScanService:
    service = current_app.extensions.get(SCANS)
    if service is None:
        abort(503, NOT_RUNNING)
    return cast(ScanService, service)


def refuse(refused: ScanRefused) -> NoReturn:
    get_db().rollback()
    if refused.reason is Refusal.NOT_RUNNING:
        abort(503, NOT_RUNNING)
    abort(REFUSAL_STATUS.get(refused.reason, 422), str(refused))
