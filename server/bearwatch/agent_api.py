"""Endpoints the Windows agent calls. Reached through the tunnel without Cloudflare Access.

  POST /api/agent/enroll     site enrollment key   -> device token
  POST /api/agent/heartbeat  device token          -> whether to upload, collect now, run the WUA check
  POST /api/agent/inventory  device token, gzip    -> stored, matched later by the worker

The heartbeat carries the hash of the agent's latest inventory, so an unchanged PC never
uploads. Matching runs in the worker, not in the request, so a check-in returns in
milliseconds no matter how much software a PC has.
"""

import gzip
import zlib
from datetime import timedelta

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from . import inventory, tenants
from .config import get_settings
from .db import session_scope
from .intel.common import utcnow
from .models import Device, Site

router = APIRouter(prefix="/api/agent", tags=["agent"])
MAX_BODY = 8 * 1024 * 1024  # decompressed; a large PC inventory is well under 1 MB
# On the wire, checked as the body arrives (see BodyLimit). The agent always gzips; a real
# inventory is about 10 KB compressed, and enroll and heartbeat are a few hundred bytes.
WIRE_LIMITS = (("/api/agent/inventory", 2 * 1024 * 1024), ("/api/agent/", 16 * 1024))


class BodyLimit:
    """ASGI middleware that caps request bodies on the agent API, which is reachable without
    Cloudflare Access. A declared Content-Length over the cap is refused before any byte is
    read; a chunked body is counted as it streams and refused the moment it passes the cap."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        limit = None
        if scope["type"] == "http":
            limit = next((n for prefix, n in WIRE_LIMITS if scope["path"].startswith(prefix)), None)
        if limit is None:
            return await self.app(scope, receive, send)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"detail":"request body too large"}'})
            return
        seen = 0

        async def limited():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, "request body too large")
            return msg

        await self.app(scope, limited, send)


class EnrollRequest(BaseModel):
    enroll_key: str = Field(min_length=10, max_length=100)
    machine_guid: str = Field(pattern=r"^[0-9A-Fa-f-]{32,40}$")
    hostname: str = Field(min_length=1, max_length=255)
    agent_version: str = Field(max_length=32)


class Heartbeat(BaseModel):
    agent_version: str = Field(max_length=32)
    inventory_hash: str | None = Field(default=None, max_length=64)


def _token(authorization: str) -> str:
    return authorization.removeprefix("Bearer ").strip()


def _plan(dev: Device, site: Site, inventory_hash: str | None) -> dict:
    cfg, now = get_settings(), utcnow()
    stale = dev.last_inventory_at is None or now - dev.last_inventory_at > timedelta(days=cfg.inventory_refresh_days)
    wua_due = site.wua_check and (dev.wua_checked_at is None or now - dev.wua_checked_at > timedelta(days=cfg.wua_interval_days))
    return {
        "upload": bool(dev.rescan_requested or stale or (inventory_hash and inventory_hash != dev.inventory_hash)),
        "collect_now": bool(dev.rescan_requested),
        "wua_due": bool(wua_due),
        "heartbeat_seconds": cfg.heartbeat_seconds,
        "collect_seconds": cfg.collect_seconds,
    }


@router.post("/enroll")
def enroll(req: EnrollRequest) -> dict:
    with session_scope() as s:
        site = tenants.site_for_key(s, req.enroll_key.strip())
        if site is None:
            raise HTTPException(401, "unknown enrollment key")
        dev, token = tenants.enroll(s, site, req.machine_guid.lower(), req.hostname, req.agent_version)
        return {"device_id": dev.id, "token": token, **_plan(dev, site, None)}


@router.post("/heartbeat")
def heartbeat(hb: Heartbeat, authorization: str = Header(default="")) -> dict:
    with session_scope() as s:
        dev = tenants.device_for_token(s, _token(authorization))
        if dev is None:
            raise HTTPException(401, "unknown device token; re-enroll")
        dev.last_seen, dev.agent_version = utcnow(), hb.agent_version
        return _plan(dev, s.get(Site, dev.site_id), hb.inventory_hash)


@router.post("/inventory", status_code=202)
async def upload_inventory(request: Request, authorization: str = Header(default="")) -> dict:
    # Check the token before reading the body, so a stranger costs one indexed lookup.
    with session_scope() as s:
        dev = tenants.device_for_token(s, _token(authorization))
        if dev is None:
            raise HTTPException(401, "unknown device token; re-enroll")
        device_id = dev.id
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, MAX_BODY)
            if d.unconsumed_tail:
                raise HTTPException(413, "inventory too large")
        except (zlib.error, gzip.BadGzipFile) as e:
            raise HTTPException(400, "bad gzip body") from e
    elif len(raw) > MAX_BODY:
        raise HTTPException(413, "inventory too large")
    try:
        inv = inventory.Inventory.model_validate_json(raw)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False, include_context=False)) from e
    with session_scope() as s:
        dev = s.get(Device, device_id)
        if dev is None:  # deleted while the body was in flight
            raise HTTPException(401, "unknown device token; re-enroll")
        inventory.store(s, dev, inv)
    return {"accepted": True}
