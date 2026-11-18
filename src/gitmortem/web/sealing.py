from typing import cast

from flask import current_app

from gitmortem.crypto import Sealer

SEALER = "gitmortem.sealer"


def app_sealer() -> Sealer:
    return cast(Sealer, current_app.extensions[SEALER])
