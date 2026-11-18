from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("login_throttle")
    op.create_table(
        "login_throttle",
        sa.Column("key_hmac", sa.String(length=64), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("first_failed_at", UTCDateTime(), nullable=False),
        sa.Column("locked_until", UTCDateTime(), nullable=True),
        sa.PrimaryKeyConstraint("key_hmac"),
    )
