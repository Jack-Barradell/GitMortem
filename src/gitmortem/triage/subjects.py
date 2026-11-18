from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from gitmortem.db.models import Finding, Secret


class SubjectKind(StrEnum):
    SECRET = "secret"  # noqa: S105
    FINDING = "finding"


@dataclass(frozen=True, order=True)
class Subject:
    kind: SubjectKind
    id: int


class NoSuchSubject(LookupError):
    def __init__(self, subject: Subject) -> None:
        super().__init__(f"no {subject.kind.value} {subject.id} to triage")
        self.subject = subject


def subject_key(subject: Subject) -> str:
    return f"{subject.kind.value}:{subject.id}"


def columns(subject: Subject) -> dict[str, int | None]:
    return {
        "secret_id": subject.id if subject.kind is SubjectKind.SECRET else None,
        "finding_id": subject.id if subject.kind is SubjectKind.FINDING else None,
    }


def subject_of_finding(finding: Finding) -> Subject:
    if finding.secret_id is not None:
        return Subject(SubjectKind.SECRET, finding.secret_id)
    return Subject(SubjectKind.FINDING, finding.id)


def require(session: Session, subject: Subject) -> Secret | Finding:
    row: Secret | Finding | None
    if subject.kind is SubjectKind.SECRET:
        row = session.get(Secret, subject.id)
    else:
        row = session.get(Finding, subject.id)
        if row is not None and row.secret_id is not None:
            row = None
    if row is None:
        raise NoSuchSubject(subject)
    return row
