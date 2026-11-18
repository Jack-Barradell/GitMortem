from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from gitmortem.crypto import Purpose, Sealer

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BATCH = 1000
NEEDS_KEY = (
    "sealing the stored commit messages needs the instance key: start GitMortem once "
    "(gitmortem local or serve) to upgrade this database"
)


def _sealer() -> Sealer:
    config = op.get_context().config
    key = None if config is None else config.attributes.get("instance_key")
    if not isinstance(key, bytes):
        raise RuntimeError(NEEDS_KEY)
    return Sealer(key)


def upgrade() -> None:
    op.add_column("findings", sa.Column("message_sealed", sa.LargeBinary(), nullable=True))
    op.add_column("instance_settings", sa.Column("key_check", sa.String(length=64), nullable=True))
    bind = op.get_bind()
    held = bind.execute(
        sa.text("SELECT count(*) FROM findings WHERE commit_message IS NOT NULL")
    ).scalar_one()
    if held:
        sealer = _sealer()
        last = 0
        while True:
            rows = bind.execute(
                sa.text(
                    "SELECT id, commit_message FROM findings"
                    " WHERE commit_message IS NOT NULL AND id > :last ORDER BY id LIMIT :n"
                ),
                {"last": last, "n": BATCH},
            ).all()
            if not rows:
                break
            bind.execute(
                sa.text(
                    "UPDATE findings SET message_sealed = :sealed, commit_message = NULL"
                    " WHERE id = :id"
                ),
                [
                    {
                        "id": row.id,
                        "sealed": sealer.seal(row.commit_message.encode(), Purpose.FINDING_MESSAGE),
                    }
                    for row in rows
                ],
            )
            last = rows[-1].id
    op.execute("ALTER TABLE findings DROP COLUMN commit_message")


def downgrade() -> None:
    op.add_column("findings", sa.Column("commit_message", sa.String(), nullable=True))
    bind = op.get_bind()
    held = bind.execute(
        sa.text("SELECT count(*) FROM findings WHERE message_sealed IS NOT NULL")
    ).scalar_one()
    if held:
        sealer = _sealer()
        rows = bind.execute(
            sa.text("SELECT id, message_sealed FROM findings WHERE message_sealed IS NOT NULL")
        ).all()
        bind.execute(
            sa.text("UPDATE findings SET commit_message = :message WHERE id = :id"),
            [
                {
                    "id": row.id,
                    "message": sealer.open(row.message_sealed, Purpose.FINDING_MESSAGE).decode(),
                }
                for row in rows
            ],
        )
    op.execute("ALTER TABLE findings DROP COLUMN message_sealed")
    op.execute("ALTER TABLE instance_settings DROP COLUMN key_check")
