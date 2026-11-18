from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instance_settings", sa.Column("canary_words_sealed", sa.LargeBinary(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("instance_settings", "canary_words_sealed")
