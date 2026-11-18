from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_event_subjects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["event_id"], ["audit_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("audit_event_subjects", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_audit_event_subjects_event_id"), ["event_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_audit_event_subjects_finding_id"), ["finding_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_audit_event_subjects_secret_id"), ["secret_id"], unique=False
        )

    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("author_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("edited_by_user_id", sa.Integer(), nullable=True),
        sa.Column("edited_at", UTCDateTime(), nullable=True),
        sa.Column("text_sealed", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["author_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["edited_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("notes", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_notes_finding_id"), ["finding_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_notes_secret_id"), ["secret_id"], unique=False)

    op.create_table(
        "status_changes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column(
            "from_status",
            sa.Enum(
                "unclassified",
                "to_review",
                "unsure",
                "valid",
                "invalid",
                "false_positive",
                "revoked",
                name="secretstatus",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "to_status",
            sa.Enum(
                "unclassified",
                "to_review",
                "unsure",
                "valid",
                "invalid",
                "false_positive",
                "revoked",
                name="secretstatus",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("at", UTCDateTime(), nullable=False),
        sa.Column("batch_id", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("status_changes", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_status_changes_finding_id"), ["finding_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_status_changes_secret_id"), ["secret_id"], unique=False
        )

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "status",
                sa.Enum(
                    "unclassified",
                    "to_review",
                    "unsure",
                    "valid",
                    "invalid",
                    "false_positive",
                    "revoked",
                    name="secretstatus",
                    native_enum=False,
                    length=32,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("commit_message", sa.String(), nullable=True))

    op.execute("UPDATE findings SET status = 'unclassified' WHERE value_hash = ''")
