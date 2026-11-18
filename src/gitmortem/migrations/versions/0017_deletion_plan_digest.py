from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("deletions", sa.Column("plan_digest", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.execute("ALTER TABLE deletions DROP COLUMN plan_digest")
