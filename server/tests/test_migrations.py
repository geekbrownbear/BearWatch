import os

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text

from bearwatch import db
from bearwatch.models import Base


def test_migrations_match_models(tmp_path):
    """Upgrading an empty database must produce exactly the schema the models describe."""
    url = f"sqlite:///{tmp_path / 'm.db'}"
    engine = db.init_db(url)
    with engine.begin() as conn:
        command.check(db._alembic_config(conn))  # raises if models and migrations differ
        assert conn.execute(text("select version_num from alembic_version")).scalar() == "0005"


def test_pre_alembic_database_is_stamped(tmp_path):
    """A Phase 0 database (built with create_all, no alembic_version) keeps its data and gains the new tables."""
    url = f"sqlite:///{tmp_path / 'old.db'}"
    old = create_engine(url)
    phase0 = [t for name, t in Base.metadata.tables.items() if name in {"cve", "cpe_match", "kev", "epss", "ssvc", "sync_state", "winget_package", "msrc_document", "msrc_product", "msrc_vuln", "msrc_fix"}]
    Base.metadata.create_all(old, tables=phase0)
    with old.begin() as conn:
        conn.execute(text("drop index ix_cpe_match_product"))  # added in 0002, not in Phase 0 databases
        conn.execute(text("insert into cve (id) values ('CVE-2024-0001')"))
    old.dispose()

    engine = db.init_db(url)
    with engine.connect() as conn:
        assert conn.execute(text("select count(*) from cve")).scalar() == 1
        assert {"device", "finding", "client"} <= set(inspect(conn).get_table_names())


# Points at a throwaway Postgres database; the test drops every table in it. CI sets this.
PG_URL = os.environ.get("BEARWATCH_TEST_POSTGRES_URL")


@pytest.mark.skipif(not PG_URL, reason="set BEARWATCH_TEST_POSTGRES_URL to a throwaway Postgres database")
def test_postgres_upgrade_downgrade_upgrade():
    """Every migration runs both ways on Postgres, which the SQLite tests can miss."""
    engine = db.init_db(PG_URL)
    try:
        with engine.begin() as conn:
            cfg = db._alembic_config(conn)
            command.check(cfg)
            command.downgrade(cfg, "base")
            assert set(inspect(conn).get_table_names()) <= {"alembic_version"}
            command.upgrade(cfg, "head")
            command.check(cfg)
    finally:
        engine.dispose()
