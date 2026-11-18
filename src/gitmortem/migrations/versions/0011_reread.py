from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "kind",
                sa.Enum("scan", "import", "reread", name="scankind", native_enum=False, length=32),
                server_default="scan",
                nullable=False,
            )
        )

    with op.batch_alter_table("tool_runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("reread_of_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("parts_run_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("superseded_by_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("superseded_at", UTCDateTime(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_tool_runs_reread_of_id"), ["reread_of_id"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_tool_runs_superseded_by_id_tool_runs", "tool_runs", ["superseded_by_id"], ["id"]
        )
        batch_op.create_foreign_key(
            "fk_tool_runs_reread_of_id_tool_runs", "tool_runs", ["reread_of_id"], ["id"]
        )
        batch_op.create_foreign_key(
            "fk_tool_runs_parts_run_id_tool_runs", "tool_runs", ["parts_run_id"], ["id"]
        )
