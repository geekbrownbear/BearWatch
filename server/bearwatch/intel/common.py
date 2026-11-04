"""Shared helpers for feed sync: HTTP client, retries, date parsing, run bookkeeping."""

import logging
import time
from collections.abc import Callable
from datetime import UTC, date, datetime

import httpx
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import session_scope
from ..models import SyncState

log = logging.getLogger("bearwatch.intel")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def make_client(timeout: float = 120.0) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": get_settings().user_agent},
    )


def get_with_retry(client: httpx.Client, url: str, *, tries: int = 5, backoff: float = 6.0, **kw) -> httpx.Response:
    """GET with backoff on throttling and transient server errors (NVD returns 403/503 under load)."""
    last: Exception | None = None
    for attempt in range(tries):
        try:
            r = client.get(url, **kw)
            if r.status_code in (403, 429, 500, 502, 503, 504):
                raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            return r
        except (httpx.TransportError, httpx.HTTPStatusError) as e:
            last = e
            if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 404:
                raise
            wait = backoff * (attempt + 1)
            log.warning("GET %s failed (%s), retry in %.0fs", url, e, wait)
            time.sleep(wait)
    assert last is not None
    raise last


def parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    v = v.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def parse_date(v: str | None) -> date | None:
    if not v:
        return None
    try:
        return date.fromisoformat(v[:10])
    except ValueError:
        return None


def run_sync(source: str, fn: Callable[[Session], int]) -> int:
    """Run one source's sync and record the outcome in sync_state."""
    with session_scope() as s:
        state = s.get(SyncState, source) or SyncState(source=source)
        state.last_started = utcnow()
        state.last_status = "running"
        s.merge(state)
    try:
        with session_scope() as s:
            rows = fn(s)
    except Exception as e:
        with session_scope() as s:
            state = s.get(SyncState, source)
            assert state is not None
            state.last_status = "error"
            state.last_error = f"{type(e).__name__}: {e}"[:4000]
        log.exception("sync %s failed", source)
        raise
    with session_scope() as s:
        state = s.get(SyncState, source)
        assert state is not None
        state.last_status = "ok"
        state.last_success = utcnow()
        state.last_error = None
        state.rows = rows
    log.info("sync %s ok: %d rows", source, rows)
    return rows
