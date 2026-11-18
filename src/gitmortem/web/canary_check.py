from collections.abc import Collection, Mapping

from sqlalchemy.orm import Session

from gitmortem.crypto import Sealer
from gitmortem.triage import canary, values
from gitmortem.triage.canary import Hint
from gitmortem.triage.subjects import Subject
from gitmortem.web.heavy import spare_slot

__all__ = ["possible_canaries", "subject_hints"]


def possible_canaries(
    db: Session,
    sealer: Sealer,
    subjects: Collection[Subject],
    opened: values.Opened,
    *,
    holding: bool = False,
    shown: Mapping[Subject, str] | None = None,
) -> tuple[set[Subject], bool]:
    behind = canary.findings_behind(db, subjects)
    if behind > canary.MAX_CHECKED_FINDINGS:
        return set(), True
    with spare_slot(behind > canary.MAX_CHEAP_FINDINGS and not holding) as free:
        if not free:
            return set(), True
        try:
            chosen = canary.words(db, sealer)
            found = canary.canary_subjects(db, sealer, subjects, chosen, opened=opened, shown=shown)
        except (canary.TooManyToCheck, values.TooManyToDecrypt):
            return set(), True
    return found, False


def subject_hints(db: Session, sealer: Sealer, subject: Subject) -> tuple[list[Hint], bool, bool]:
    behind = canary.findings_behind(db, [subject])
    if behind > canary.MAX_CHECKED_FINDINGS:
        return [], False, True
    with spare_slot(behind > canary.MAX_CHEAP_FINDINGS) as free:
        if not free:
            return [], False, True
        try:
            hints, more = canary.hints_of(
                db, sealer, subject, canary.words(db, sealer), opened=values.Opened()
            )
        except (canary.TooManyToCheck, values.TooManyToDecrypt):
            return [], False, True
    return hints, more, False
