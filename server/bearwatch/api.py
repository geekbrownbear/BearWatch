"""HTTP app: API-token endpoints (intel status, matchers), the agent API and the dashboard."""

import hmac
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import __version__, agent_api, auth, web
from .config import get_settings
from .db import init_db, session_scope
from .match import apps, windows
from .models import SyncState


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="BearWatch", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(agent_api.router)
app.include_router(web.router)
app.mount("/static", StaticFiles(directory=web.STATIC), name="static")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


class SecurityHeaders:
    """Plain ASGI rather than @app.middleware("http"): that style reads the request in a
    separate task, so errors raised while reading the body (BodyLimit) would escape."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def with_headers(msg):
            if msg["type"] == "http.response.start":
                present = {k.lower() for k, _ in msg.get("headers", [])}
                extra = [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items() if k.lower().encode() not in present]
                msg = {**msg, "headers": [*msg.get("headers", []), *extra]}
            await send(msg)

        await self.app(scope, receive, with_headers)


app.add_middleware(SecurityHeaders)
# Added last, so it is the outermost of our middleware and sees the body first.
app.add_middleware(agent_api.BodyLimit)


@app.exception_handler(auth.NotSignedIn)
async def not_signed_in(_request: Request, _exc: auth.NotSignedIn):
    return RedirectResponse("/login", 303)


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
