from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TOOLS = ("git-secrets", "gitleaks", "trufflehog", "custom-rules")
NOT_ON_DISK_HAS_NO_PLACE = (
    "(kind = 'not_on_disk' AND scan_root_id IS NULL AND rel_path IS NULL AND git_dir IS NULL)"
    " OR (kind != 'not_on_disk' AND scan_root_id IS NOT NULL AND rel_path IS NOT NULL"
    " AND git_dir IS NOT NULL)"
)


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32)


def upgrade() -> None:
    for table in ("secrets", "findings", "status_changes", "notes"):
        with op.batch_alter_table(
            table, recreate="always", table_kwargs={"sqlite_autoincrement": True}
        ):
            pass

    subjects = sa.Table(
        "audit_event_subjects",
        sa.MetaData(),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["event_id"], ["audit_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_audit_event_subjects_event_id", "event_id"),
        sa.Index("ix_audit_event_subjects_finding_id", "finding_id"),
        sa.Index("ix_audit_event_subjects_secret_id", "secret_id"),
    )
    with op.batch_alter_table("audit_event_subjects", recreate="always", copy_from=subjects):
        pass

    with op.batch_alter_table("repositories", schema=None) as batch_op:
        batch_op.alter_column("scan_root_id", existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("rel_path", existing_type=sa.LargeBinary(), nullable=True)
        batch_op.alter_column("git_dir", existing_type=sa.LargeBinary(), nullable=True)
        batch_op.alter_column(
            "kind",
            existing_type=_enum("repositorykind", "work_tree", "bare"),
            type_=_enum("repositorykind", "work_tree", "bare", "not_on_disk"),
            existing_nullable=False,
        )
        batch_op.create_check_constraint(
            "ck_repositories_not_on_disk_has_no_place", NOT_ON_DISK_HAS_NO_PLACE
        )
        batch_op.create_index(
            "ux_repositories_not_on_disk",
            ["org", "name"],
            unique=True,
            sqlite_where=sa.text("kind = 'not_on_disk'"),
        )

    with op.batch_alter_table("sightings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("reported_live", sa.Boolean(), nullable=True))

    op.create_table(
        "imports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("tool", _enum("toolname", *TOOLS), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            _enum(
                "importstate",
                "uploading",
                "checking",
                "checked",
                "recording",
                "recorded",
                "discarded",
                "removed",
                "failed",
            ),
            nullable=False,
        ),
        sa.Column("source", _enum("importsource", "upload", "server_file"), nullable=False),
        sa.Column("client_name", sa.String(length=255), nullable=True),
        sa.Column("server_path", sa.String(length=4096), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("pieces", sa.Integer(), nullable=False),
        sa.Column("pieces_received", sa.Integer(), nullable=False),
        sa.Column("check", sa.JSON(), nullable=True),
        sa.Column(
            "failure",
            _enum(
                "importfailure",
                "wrong_format",
                "no_commits",
                "hosted_source",
                "too_large",
                "unreadable",
                "repository_unavailable",
                "unexpected_error",
            ),
            nullable=True,
        ),
        sa.Column("failure_reason", sa.String(length=128), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.Column("recorded_at", UTCDateTime(), nullable=True),
        sa.Column("removed_at", UTCDateTime(), nullable=True),
        sa.Column("removed_by_user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["removed_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    with op.batch_alter_table("imports", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_imports_repository_id"), ["repository_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_imports_state"), ["state"], unique=False)
