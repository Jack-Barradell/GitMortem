from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("message_cut", sa.Boolean(), server_default=sa.text("0"), nullable=False)
        )
        batch_op.add_column(
            sa.Column(
                "place",
                sa.Enum(
                    "line",
                    "binary",
                    "message",
                    "unresolved",
                    name="findingplace",
                    native_enum=False,
                    length=32,
                ),
                server_default="line",
                nullable=False,
            )
        )

    op.execute(
        "UPDATE findings SET message_cut = 1"
        " WHERE commit_message IS NOT NULL AND length(CAST(commit_message AS BLOB)) >= 4093"
    )
