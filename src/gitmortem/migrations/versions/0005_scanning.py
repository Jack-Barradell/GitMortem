from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "instance_settings",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("scan_workers", sa.Integer(), server_default="2", nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "secrets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("value_sealed", sa.LargeBinary(), nullable=False),
        sa.Column("preview", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
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
            server_default="unclassified",
            nullable=False,
        ),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value_hash"),
    )
    op.create_table(
        "scan_roots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("added_by_user_id", sa.Integer(), nullable=True),
        sa.Column("added_at", UTCDateTime(), nullable=False),
        sa.Column("removed_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["added_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("path"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("started_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "state",
            sa.Enum(
                "queued",
                "running",
                "finished",
                "cancelled",
                "interrupted",
                name="scanstate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("workers", sa.Integer(), nullable=False),
        sa.Column("cancel_requested_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=True),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["started_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "tool_settings",
        sa.Column(
            "tool",
            sa.Enum("git-secrets", name="toolname", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("1"), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), server_default="1800", nullable=False),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("tool"),
    )
    op.create_table(
        "discovery_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_root_id", sa.Integer(), nullable=False),
        sa.Column("started_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "state",
            sa.Enum(
                "queued",
                "running",
                "done",
                "failed",
                "cancelled",
                "interrupted",
                name="discoverystate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("found", sa.Integer(), nullable=False),
        sa.Column("refused", sa.Integer(), nullable=False),
        sa.Column("aliases", sa.Integer(), nullable=False),
        sa.Column("not_followed", sa.Integer(), nullable=False),
        sa.Column("cancel_requested_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=True),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_root_id"],
            ["scan_roots.id"],
        ),
        sa.ForeignKeyConstraint(["started_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("discovery_runs", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_discovery_runs_scan_root_id"), ["scan_root_id"], unique=False
        )

    op.create_table(
        "repositories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_root_id", sa.Integer(), nullable=False),
        sa.Column("rel_path", sa.LargeBinary(), nullable=False),
        sa.Column("display_path", sa.String(), nullable=False),
        sa.Column("org", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum("work_tree", "bare", name="repositorykind", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("git_dir", sa.LargeBinary(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "scannable",
                "refused",
                "missing",
                name="repositorystate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "refusal",
            sa.Enum(
                "own_alternates",
                "sha256",
                "shallow",
                "outside_root",
                "unreadable",
                name="repositoryrefusal",
                native_enum=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("commit_count", sa.Integer(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("head", sa.String(), nullable=True),
        sa.Column("first_seen_at", UTCDateTime(), nullable=False),
        sa.Column("last_seen_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_root_id"],
            ["scan_roots.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("git_dir"),
        sa.UniqueConstraint("scan_root_id", "rel_path"),
    )
    with op.batch_alter_table("repositories", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_repositories_scan_root_id"), ["scan_root_id"], unique=False
        )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column(
            "tool",
            sa.Enum("git-secrets", name="toolname", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("rule", sa.String(), nullable=False),
        sa.Column("commit", sa.String(length=64), nullable=False),
        sa.Column("path", sa.LargeBinary(), nullable=False),
        sa.Column("display_path", sa.String(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("value_sealed", sa.LargeBinary(), nullable=True),
        sa.Column("match_sealed", sa.LargeBinary(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=True),
        sa.Column("author_name", sa.String(), nullable=False),
        sa.Column("author_email", sa.String(), nullable=False),
        sa.Column("authored_at", UTCDateTime(), nullable=True),
        sa.Column("first_seen_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "repository_id", "tool", "rule", "commit", "path", "line", "value_hash"
        ),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_findings_repository_id"), ["repository_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_findings_secret_id"), ["secret_id"], unique=False)

    op.create_table(
        "tool_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column(
            "tool",
            sa.Enum("git-secrets", name="toolname", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("identity", sa.String(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "queued",
                "running",
                "done",
                "failed",
                "timed_out",
                "cancelled",
                "interrupted",
                name="toolrunstate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "failure",
            sa.Enum(
                "outside_root",
                "shadow_refused",
                "unreadable",
                "unsafe_work_tree",
                "unexpected_output",
                "exit_code",
                "tool_unavailable",
                name="toolrunfailure",
                native_enum=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column(
            "integrity",
            sa.Enum(
                "not_checked",
                "verified",
                "failed",
                "timed_out",
                name="integritystate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("parse_issues", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("raw_parts", sa.JSON(), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=True),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("tool_runs", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_tool_runs_repository_id"), ["repository_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_tool_runs_scan_id"), ["scan_id"], unique=False)

    op.create_table(
        "sightings",
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("tool_run_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.ForeignKeyConstraint(
            ["tool_run_id"],
            ["tool_runs.id"],
        ),
        sa.PrimaryKeyConstraint("finding_id", "tool_run_id"),
    )
    with op.batch_alter_table("sightings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_sightings_tool_run_id"), ["tool_run_id"], unique=False)
