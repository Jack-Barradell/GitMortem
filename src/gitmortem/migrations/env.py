from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext

from gitmortem.db.models import Base, UTCDateTime


def render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    if type_ == "type" and isinstance(obj, UTCDateTime):
        autogen_context.imports.add("from gitmortem.migrations.column_types import UTCDateTime")
        return "UTCDateTime()"
    return False


connection = context.config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=True,
    render_item=render_item,
    process_revision_directives=context.config.attributes.get("process_revision_directives"),
)
with context.begin_transaction():
    context.run_migrations()
