from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(
            "ix_findings_secret_repository_tool",
            ["secret_id", "repository_id", "tool"],
            unique=False,
        )

    with op.batch_alter_table("imports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("checked_at", UTCDateTime(), nullable=True))

    op.execute(
        sa.text("UPDATE imports SET checked_at = :now WHERE state = 'checked'").bindparams(
            now=datetime.now(UTC).isoformat(timespec="microseconds")
        )
    )
