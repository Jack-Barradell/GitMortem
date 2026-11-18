from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tool_runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("coverage_gaps", sa.JSON(), nullable=True))
