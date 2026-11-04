"""Alembic environment. Run through bearwatch.db.migrate(), not the alembic CLI."""

from alembic import context

from bearwatch.db import get_engine
from bearwatch.models import Base

config = context.config
target_metadata = Base.metadata


def run() -> None:
    conn = config.attributes.get("connection")
    if conn is None:
        with get_engine().connect() as conn:
            _run(conn)
    else:
        _run(conn)


def _run(conn) -> None:
    context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=conn.dialect.name == "sqlite", compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


run()
