from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.migrations.column_types import UTCDateTime

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REPOSITORY_PLACE = (
    "(kind = 'not_on_disk' AND scan_root_id IS NULL AND rel_path IS NULL AND git_dir IS NULL)"
    " OR (kind = 'uploaded' AND scan_root_id IS NULL AND rel_path IS NULL"
    " AND git_dir IS NOT NULL)"
    " OR (kind NOT IN ('not_on_disk', 'uploaded') AND scan_root_id IS NOT NULL"
    " AND rel_path IS NOT NULL AND git_dir IS NOT NULL)"
)


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32)


def upgrade() -> None:
    op.create_table(
        "deletions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "state",
            sa.Enum(
                "queued", "running", "done", name="deletionjobstate", native_enum=False, length=32
            ),
            nullable=False,
        ),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=True),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )
    with op.batch_alter_table("deletions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_deletions_state"), ["state"], unique=False)

    op.create_table(
        "uploads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("client_name", sa.String(length=255), nullable=False),
        sa.Column("org_prefix", sa.String(length=100), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("last_modified_ms", sa.Integer(), nullable=False),
        sa.Column("pieces_received", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "uploading",
                "queued",
                "processing",
                "waiting",
                "done",
                "failed",
                "discarded",
                name="uploadstate",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "failure",
            sa.Enum(
                "not_a_zip",
                "multi_disk",
                "truncated",
                "too_many_entries",
                "too_large_unpacked",
                "overlapping",
                "backslash_names",
                "encrypted",
                "bad_central_directory",
                "disk_full",
                "no_repos",
                "pieces_unreadable",
                "interrupted",
                "unexpected_error",
                name="uploadfailure",
                native_enum=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )
    with op.batch_alter_table("uploads", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_uploads_state"), ["state"], unique=False)

    op.create_table(
        "upload_repos",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("zip_path", sa.String(length=4096), nullable=False),
        sa.Column("org", sa.String(length=100), nullable=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "pending",
                "new",
                "replaced",
                "new_version",
                "waiting",
                "answered",
                "refused",
                "discarded",
                name="uploadrepooutcome",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "refusal",
            sa.Enum(
                "ambiguous_case",
                "git_file_outside",
                "not_a_repo",
                "bad_entry_name",
                "link_or_device",
                "name_collision",
                "unreadable",
                "shallow",
                "sha256",
                "partial_clone",
                name="uploadreporefusal",
                native_enum=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("repository_id", sa.Integer(), nullable=True),
        sa.Column("candidates", sa.JSON(), nullable=False),
        sa.Column("pending_dir", sa.LargeBinary(), nullable=True),
        sa.Column("answered_by_user_id", sa.Integer(), nullable=True),
        sa.Column("answered_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["answered_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
        ),
        sa.ForeignKeyConstraint(
            ["upload_id"],
            ["uploads.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )
    with op.batch_alter_table("upload_repos", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_upload_repos_repository_id"), ["repository_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_upload_repos_upload_id"), ["upload_id"], unique=False)

    op.create_table(
        "repository_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column("upload_repo_id", sa.Integer(), nullable=False),
        sa.Column("git_dir", sa.LargeBinary(), nullable=False),
        sa.Column("current", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("removed_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
        ),
        sa.ForeignKeyConstraint(
            ["upload_repo_id"],
            ["upload_repos.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("git_dir"),
        sa.UniqueConstraint("upload_repo_id"),
        sqlite_autoincrement=True,
    )
    with op.batch_alter_table("repository_versions", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_repository_versions_repository_id"), ["repository_id"], unique=False
        )

    with op.batch_alter_table("instance_settings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("upload_bytes", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("zip_entries", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("unpacked_bytes", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("ratio", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("import_bytes", sa.Integer(), nullable=True))

    with op.batch_alter_table("repositories", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "deletion_state",
                sa.Enum(
                    "deleting",
                    "failed",
                    "deleted",
                    name="deletionstate",
                    native_enum=False,
                    length=32,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "deletion_failure",
                sa.Enum(
                    "files_not_deleted",
                    "scans_still_running",
                    "unexpected_error",
                    name="deletionfailure",
                    native_enum=False,
                    length=32,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("deletion_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("deleted_at", UTCDateTime(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_repositories_deletion_id"), ["deletion_id"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_repositories_deletion_id_deletions", "deletions", ["deletion_id"], ["id"]
        )
        batch_op.alter_column(
            "kind",
            existing_type=_enum("repositorykind", "work_tree", "bare", "not_on_disk"),
            type_=_enum("repositorykind", "work_tree", "bare", "not_on_disk", "uploaded"),
            existing_nullable=False,
        )
        batch_op.drop_constraint("ck_repositories_not_on_disk_has_no_place", type_="check")
        batch_op.create_check_constraint(
            "ck_repositories_not_on_disk_has_no_place", REPOSITORY_PLACE
        )
