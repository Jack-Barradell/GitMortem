from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE tool_runs SET coverage_gaps = json_remove(coverage_gaps, '$.matches_capped')"
        " WHERE coverage_gaps IS NOT NULL"
        " AND json_type(coverage_gaps, '$.matches_capped') IS NOT NULL"
    )


def downgrade() -> None:
    pass
