from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tool_runs", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("kept_end", sa.Boolean(), server_default=sa.text("0"), nullable=False)
        )

    op.execute(
        "UPDATE tool_runs SET kept_end = 1"
        " WHERE reread_of_id IS NOT NULL AND parser_version IS NOT NULL AND EXISTS ("
        " SELECT 1 FROM tool_runs AS parts WHERE parts.id = tool_runs.parts_run_id"
        " AND parts.state = tool_runs.state AND parts.failure IS tool_runs.failure"
        " AND (parts.state IN ('timed_out', 'cancelled', 'interrupted')"
        " OR (parts.state = 'failed' AND parts.parser_version IS NULL))"
        " AND NOT EXISTS (SELECT 1 FROM imports WHERE imports.scan_id = parts.scan_id))"
    )
