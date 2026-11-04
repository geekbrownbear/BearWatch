"""Engine, sessions and a portable bulk upsert (Postgres in production, SQLite in tests)."""

from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

_engine: Engine | None = None
_Session: sessionmaker | None = None


def get_engine(url: str | None = None) -> Engine:
    global _engine, _Session
    if url is not None or _engine is None:
        url = url or get_settings().database_url
        kwargs: dict[str, Any] = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            kwargs["pool_pre_ping"] = True
        _engine = create_engine(url, **kwargs)
        _Session = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def init_db(url: str | None = None) -> Engine:
    """Create tables if missing. Alembic migrations replace this in Phase 1."""
    from . import models  # noqa: F401  (registers tables)

    engine = get_engine(url)
    models.Base.metadata.create_all(engine)
    return engine


@contextmanager
def session_scope() -> Iterator[Session]:
    if _Session is None:
        get_engine()
    assert _Session is not None
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def chunked(rows: Sequence[Any] | Iterable[Any], size: int = 1000) -> Iterator[list[Any]]:
    batch: list[Any] = []
    for r in rows:
        batch.append(r)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def upsert(session: Session, model: Any, rows: list[dict], key: Sequence[str], chunk: int = 1000) -> int:
    """Insert rows, updating every non-key column on conflict. Returns rows written."""
    if not rows:
        return 0
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:  # pragma: no cover
        raise RuntimeError(f"upsert not supported on {dialect}")

    cols = [c.name for c in model.__table__.columns]
    # SQLite and Postgres both cap bound parameters; keep each statement well under that.
    per_stmt = max(1, min(chunk, 30000 // max(1, len(cols))))
    written = 0
    for batch in chunked(rows, per_stmt):
        stmt = insert(model).values(batch)
        update = {c: stmt.excluded[c] for c in cols if c not in key and c in batch[0]}
        stmt = stmt.on_conflict_do_update(index_elements=list(key), set_=update) if update else stmt.on_conflict_do_nothing(index_elements=list(key))
        session.execute(stmt)
        written += len(batch)
    return written
