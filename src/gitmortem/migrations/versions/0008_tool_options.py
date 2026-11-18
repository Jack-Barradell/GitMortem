from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("skipped_tools", sa.JSON(), server_default=sa.text("'{}'"), nullable=False)
        )

    with op.batch_alter_table("tool_runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("options", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("parser_version", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "canary",
                sa.Enum(
                    "seen",
                    "missing",
                    "not_checked",
                    name="canarystate",
                    native_enum=False,
                    length=32,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("canary_commit", sa.String(length=40), nullable=True))

    with op.batch_alter_table("tool_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("options", sa.JSON(), server_default=sa.text("'{}'"), nullable=False)
        )

    op.execute(
        "UPDATE tool_runs SET options = '{\"allow_aws_examples\": false}'"
        " WHERE tool = 'git-secrets'"
    )
    op.execute(
        "UPDATE tool_runs SET parser_version = 0 WHERE tool = 'git-secrets'"
        " AND (state = 'done' OR (state = 'failed' AND exit_code IS NOT NULL))"
    )
