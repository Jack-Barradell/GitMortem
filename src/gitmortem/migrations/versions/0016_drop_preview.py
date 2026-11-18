from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import sqlalchemy as sa
from alembic import op
from alembic.operations import BatchOperations

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


@contextmanager
def _rebuilt_secrets() -> Iterator[BatchOperations]:
    bind = op.get_bind()
    kept = bind.execute(sa.text("SELECT seq FROM sqlite_sequence WHERE name = 'secrets'")).scalar()
    with op.batch_alter_table(
        "secrets", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ) as batch_op:
        yield batch_op
    if kept is not None:
        bind.execute(
            sa.text("UPDATE sqlite_sequence SET seq = max(seq, :kept) WHERE name = 'secrets'"),
            {"kept": kept},
        )
        bind.execute(
            sa.text(
                "INSERT INTO sqlite_sequence (name, seq) SELECT 'secrets', :kept"
                " WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'secrets')"
            ),
            {"kept": kept},
        )


def upgrade() -> None:
    with _rebuilt_secrets() as batch_op:
        batch_op.drop_column("preview")


def downgrade() -> None:
    with _rebuilt_secrets() as batch_op:
        batch_op.add_column(
            sa.Column("preview", sa.String(), nullable=False, server_default="****")
        )
