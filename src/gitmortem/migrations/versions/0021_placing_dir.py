from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("upload_repos", sa.Column("placing_dir", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("upload_repos", "placing_dir")
