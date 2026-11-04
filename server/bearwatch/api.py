"""HTTP API. Phase 0 exposes intel status and the two matchers; agents and tenants come in Phase 1."""

import hmac
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import __version__
from .config import get_settings
from .db import init_db, session_scope
from .match import apps, windows
from .models import SyncState


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="BearWatch", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)


def require_token(authorization: str = Header(default="")) -> None:
    expected = get_settings().api_token
    supplied = authorization.removeprefix("Bearer ").strip()
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


class WindowsQuery(BaseModel):
    build: str = Field(pattern=r"^\d+\.\d+\.\d+\.\d+$")
    kbs: list[str] = []
    arch: str = "x64"
    server: bool = False
    core: bool = False
    product: str | None = None


class AppQuery(BaseModel):
    name: str = Field(min_length=1, max_length=400)
    version: str = Field(min_length=1, max_length=120)
    publisher: str | None = None


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/intel/status", dependencies=[Depends(require_token)])
def intel_status() -> list[dict]:
    with session_scope() as s:
        return [
            {
                "source": r.source,
                "status": r.last_status,
                "last_success": r.last_success,
                "rows": r.rows,
                "error": r.last_error,
            }
            for r in s.scalars(select(SyncState).order_by(SyncState.source))
        ]


@app.post("/api/match/windows", dependencies=[Depends(require_token)])
def match_windows(q: WindowsQuery) -> dict:
    product = q.product or windows.product_name(q.build, q.arch, q.server, q.core)
    if not product:
        raise HTTPException(422, f"unknown build {q.build}; send product")
    try:
        with session_scope() as s:
            r = windows.match(s, product, q.build, q.kbs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    return {
        "product": r.product,
        "build": r.build,
        "installed_kbs": r.installed_kbs,
        "fixed_count": r.fixed_count,
        "by_fix": r.by_fix,
        "open": [{"cve_id": o.cve_id, "title": o.title, "severity": o.severity, "fixes": o.fixes, **o.context.as_dict()} for o in r.open],
    }


@app.post("/api/match/app", dependencies=[Depends(require_token)])
def match_app(q: AppQuery) -> dict:
    with session_scope() as s:
        r = apps.match(s, q.name, q.version, q.publisher)
    return {**r.__dict__, "cves": [c.as_dict() for c in r.cves]}
