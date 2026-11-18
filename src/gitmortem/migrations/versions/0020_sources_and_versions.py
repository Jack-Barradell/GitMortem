from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCANNED_FINDINGS = (
    "UPDATE findings SET meta_from = CASE"
    " WHEN author_name = '' AND author_email = '' AND authored_at IS NULL THEN 'none'"
    " ELSE 'commit' END WHERE EXISTS (SELECT 1 FROM sightings"
    " JOIN tool_runs AS run ON run.id = sightings.tool_run_id"
    " LEFT JOIN tool_runs AS parts ON parts.id = run.parts_run_id"
    " JOIN scans ON scans.id = run.scan_id"
    " LEFT JOIN scans AS parts_scan ON parts_scan.id = parts.scan_id"
    " WHERE sightings.finding_id = findings.id"
    " AND (scans.kind = 'scan' OR parts_scan.kind = 'scan'))"
)
SCANNED_SECRETS = (
    "UPDATE secrets SET kind_from = 'scan' WHERE EXISTS (SELECT 1 FROM findings AS held"
    " JOIN sightings ON sightings.finding_id = held.id"
    " JOIN tool_runs AS run ON run.id = sightings.tool_run_id"
    " LEFT JOIN tool_runs AS parts ON parts.id = run.parts_run_id"
    " JOIN scans ON scans.id = run.scan_id"
    " LEFT JOIN scans AS parts_scan ON parts_scan.id = parts.scan_id"
    " WHERE held.secret_id = secrets.id"
    " AND (scans.kind = 'scan' OR parts_scan.kind = 'scan'))"
)


def _counter(table: str, column: str) -> None:
    op.add_column(
        table, sa.Column(column, sa.Integer(), server_default=sa.text("0"), nullable=False)
    )


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "meta_from",
            sa.Enum("commit", "report", "none", name="metafrom", native_enum=False, length=32),
            server_default="report",
            nullable=False,
        ),
    )
    op.add_column(
        "secrets",
        sa.Column(
            "kind_from",
            sa.Enum("scan", "import", name="kindfrom", native_enum=False, length=32),
            server_default="import",
            nullable=False,
        ),
    )
    _counter("notes", "version")
    op.add_column("tool_runs", sa.Column("binary_sha256", sa.String(length=64), nullable=True))
    _counter("upload_repos", "dropped_objects")
    _counter("uploads", "interrupted_runs")
    op.add_column(
        "users",
        sa.Column(
            "must_change_password", sa.Boolean(), server_default=sa.text("0"), nullable=False
        ),
    )
    op.execute(SCANNED_FINDINGS)
    op.execute(SCANNED_SECRETS)


def downgrade() -> None:
    for table, column in (
        ("users", "must_change_password"),
        ("uploads", "interrupted_runs"),
        ("upload_repos", "dropped_objects"),
        ("tool_runs", "binary_sha256"),
        ("notes", "version"),
        ("secrets", "kind_from"),
        ("findings", "meta_from"),
    ):
        op.drop_column(table, column)
