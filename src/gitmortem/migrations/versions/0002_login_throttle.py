from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "login_throttle",
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("first_failed_at", UTCDateTime(), nullable=False),
        sa.Column("locked_until", UTCDateTime(), nullable=True),
        sa.PrimaryKeyConstraint("username"),
    )
    with op.batch_alter_table("users") as batch:
        batch.drop_column("failed_login_count")
        batch.drop_column("first_failed_at")
        batch.drop_column("locked_until")
