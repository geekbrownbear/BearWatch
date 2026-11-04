"""Server-rendered dashboard. No JavaScript framework; every page is one query-backed template.

Findings are shown grouped by fix: one row per KB or app update, with the devices that need it
and the CVEs it closes, because that is the unit a technician actually works in.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, and_, case, cast, distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import __version__, auth, tenants
from ..config import get_settings
from ..db import session_scope
from ..intel.common import utcnow
from ..models import Client, Device, DeviceSoftware, Finding, FindingEvent, Site, SyncState, WuaUpdate

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
templates = Jinja2Templates(directory=HERE / "templates")
router = APIRouter(include_in_schema=False)

ONLINE = timedelta(minutes=35)  # two missed heartbeats
SILENT = timedelta(hours=24)


# --- template helpers ----------------------------------------------------------------------


def ago(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    sec = int((utcnow() - dt).total_seconds())
    if sec < 90:
        return "just now"
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if sec >= size:
            n = sec // size
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


def health(dev: Device) -> tuple[str, str]:
    if dev.last_seen is None:
        return "bad", "Never checked in"
    age = utcnow() - dev.last_seen
    if age <= ONLINE:
        return "ok", "Online"
    if age <= SILENT:
        return "warn", "Late"
    return "bad", "Silent"


TIER_LABEL = {1: "Exploited", 2: "Exploit code", 3: "Likely", 4: "No signal"}

templates.env.globals.update(ago=ago, health=health, tier_label=TIER_LABEL, version=__version__, quote=quote)
templates.env.filters["pct"] = lambda v: "-" if v is None else f"{v * 100:.1f}%"
templates.env.filters["score"] = lambda v: "-" if v is None else f"{v:.1f}"


def render(request: Request, name: str, user: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, {"user": user, **ctx})


# --- queries -------------------------------------------------------------------------------


def fix_rows(s: Session, client_id: int | None = None, device_id: int | None = None, limit: int | None = None) -> list[dict]:
    """Open findings grouped by fix, most urgent first."""
    q = (
        select(
            Finding.fix_key,
            func.max(Finding.fix_label).label("label"),
            func.max(Finding.subject).label("subject"),
            func.count(distinct(Finding.device_id)).label("devices"),
            func.count(distinct(Finding.cve_id)).label("cves"),
            func.min(Finding.exploit_tier).label("tier"),
            func.count(distinct(case((Finding.kev.is_(True), Finding.cve_id)))).label("kev"),
            func.max(Finding.epss).label("epss"),
            func.max(Finding.cvss).label("cvss"),
        )
        .join(Device, Device.id == Finding.device_id)
        .join(Site, Site.id == Device.site_id)
        .where(Finding.status == "open")
        .group_by(Finding.fix_key)
        .order_by(func.min(Finding.exploit_tier), func.count(distinct(Finding.device_id)).desc(), func.count(distinct(Finding.cve_id)).desc())
    )
    if client_id is not None:
        q = q.where(Site.client_id == client_id)
    if device_id is not None:
        q = q.where(Finding.device_id == device_id)
    if limit:
        q = q.limit(limit)
    return [r._asdict() for r in s.execute(q)]


def device_rows(s: Session, client_id: int | None = None) -> list[dict]:
    open_count = func.count(Finding.id)
    q = (
        select(Device, Site, open_count.label("open"), func.count(case((Finding.exploit_tier == 1, Finding.id))).label("exploited"))
        .join(Site, Site.id == Device.site_id)
        .outerjoin(Finding, and_(Finding.device_id == Device.id, Finding.status == "open"))
        .group_by(Device.id, Site.id)
        .order_by(func.count(case((Finding.exploit_tier == 1, Finding.id))).desc(), open_count.desc(), Device.hostname)
    )
    if client_id is not None:
        q = q.where(Site.client_id == client_id)
    return [{"device": d, "site": site, "open": n, "exploited": x} for d, site, n, x in s.execute(q)]


def client_rows(s: Session) -> list[dict]:
    rows = []
    for c in s.scalars(select(Client).order_by(Client.name)):
        devs = device_rows(s, c.id)
        top = fix_rows(s, client_id=c.id, limit=1)
        rows.append(
            {
                "client": c,
                "devices": len(devs),
                "silent": sum(1 for d in devs if health(d["device"])[0] == "bad"),
                "open": sum(d["open"] for d in devs),
                "exploited": sum(d["exploited"] for d in devs),
                "top_fix": top[0] if top else None,
            }
        )
    return rows


# --- sign-in -------------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None):
    if get_settings().dashboard_auth != "token":
        return RedirectResponse("/", 303)
    return templates.TemplateResponse(request, "login.html", {"user": None, "error": error})


@router.post("/login")
def login(request: Request, token: str = Form(...)):
    auth.check_origin(request)
    cfg = get_settings()
    if cfg.dashboard_auth != "token" or not cfg.api_token or not auth.hmac.compare_digest(token.strip(), cfg.api_token):
        return RedirectResponse("/login?error=1", 303)
    r = RedirectResponse("/", 303)
    r.set_cookie(auth.COOKIE, auth.session_value(cfg.api_token), httponly=True, samesite="strict", secure=request.url.scheme == "https", max_age=12 * 3600)
    return r


@router.post("/logout")
def logout(request: Request):
    auth.check_origin(request)
    r = RedirectResponse("/login", 303)
    r.delete_cookie(auth.COOKIE)
    return r


# --- pages ---------------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        clients = client_rows(s)
        fixes = fix_rows(s, limit=15)
        feeds = s.scalars(select(SyncState).order_by(SyncState.source)).all()
        return render(request, "overview.html", user, clients=clients, fixes=fixes, feeds=feeds, totals={
            "devices": sum(c["devices"] for c in clients),
            "silent": sum(c["silent"] for c in clients),
            "open": sum(c["open"] for c in clients),
            "exploited": sum(c["exploited"] for c in clients),
        })


@router.get("/clients/{client_id}", response_class=HTMLResponse)
def client_page(request: Request, client_id: int, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        client = s.get(Client, client_id) or _404()
        sites = s.scalars(select(Site).where(Site.client_id == client_id).order_by(Site.name)).all()
        return render(request, "client.html", user, client=client, sites=sites, fixes=fix_rows(s, client_id=client_id), devices=device_rows(s, client_id))


@router.get("/fix", response_class=HTMLResponse)
def fix_page(request: Request, key: str, client: int | None = None, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        q = select(Finding, Device).join(Device, Device.id == Finding.device_id).join(Site, Site.id == Device.site_id).where(Finding.fix_key == key, Finding.status == "open")
        if client is not None:
            q = q.where(Site.client_id == client)
        rows = s.execute(q.order_by(Finding.exploit_tier, Finding.epss.desc().nulls_last(), Finding.cve_id)).all()
        if not rows:
            return render(request, "fix.html", user, key=key, label=None, devices=[], cves=[], client=s.get(Client, client) if client else None)
        devices: dict[int, dict] = {}
        cves: dict[str, Finding] = {}
        for f, d in rows:
            devices.setdefault(d.id, {"device": d, "cves": 0, "version": f.subject_version})["cves"] += 1
            cves.setdefault(f.cve_id, f)
        return render(request, "fix.html", user, key=key, label=rows[0][0].fix_label, devices=sorted(devices.values(), key=lambda x: x["device"].hostname.lower()),
                      cves=list(cves.values()), client=s.get(Client, client) if client else None)


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(request: Request, device_id: int, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        dev = s.get(Device, device_id) or _404()
        site = s.get(Site, dev.site_id)
        client = s.get(Client, site.client_id)
        open_findings = s.scalars(select(Finding).where(Finding.device_id == device_id, Finding.status == "open")
                                  .order_by(Finding.exploit_tier, Finding.epss.desc().nulls_last(), Finding.cve_id)).all()
        by_fix: dict[str, list[Finding]] = {}
        for f in open_findings:
            by_fix.setdefault(f.fix_key, []).append(f)
        fixes = [r for r in fix_rows(s, device_id=device_id)]
        software = s.scalars(select(DeviceSoftware).where(DeviceSoftware.device_id == device_id).order_by(func.lower(DeviceSoftware.name))).all()
        wua = s.scalars(select(WuaUpdate).where(WuaUpdate.device_id == device_id).order_by(WuaUpdate.title)).all()
        events = s.execute(select(FindingEvent, Finding).join(Finding, Finding.id == FindingEvent.finding_id)
                           .where(FindingEvent.device_id == device_id).order_by(FindingEvent.at.desc(), FindingEvent.id.desc()).limit(40)).all()
        return render(request, "device.html", user, dev=dev, site=site, client=client, fixes=fixes, by_fix=by_fix, software=software,
                      wua=wua, cross=_cross_check(dev, open_findings, wua), events=events)


def _cross_check(dev: Device, open_findings: list[Finding], wua: list[WuaUpdate]) -> dict | None:
    """Compare the KBs BearWatch says are missing with what Windows Update itself reports."""
    if dev.wua_checked_at is None:
        return None
    ours = {f.fix_key.removeprefix("kb:") for f in open_findings if f.source == "os"}
    theirs = {w.kb for w in wua if w.kb and w.is_security}
    return {"agree": sorted(ours & theirs), "only_bearwatch": sorted(ours - theirs), "only_wua": sorted(theirs - ours), "match": ours == theirs}


@router.post("/devices/{device_id}/rescan")
def request_rescan(request: Request, device_id: int, user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        dev = s.get(Device, device_id) or _404()
        dev.rescan_requested = True
    return RedirectResponse(f"/devices/{device_id}", 303)


@router.get("/software", response_class=HTMLResponse)
def software_page(request: Request, user: str = Depends(auth.current_user)):
    """Programs that produce no findings because they are not in the overrides file yet."""
    with session_scope() as s:
        q = (
            select(DeviceSoftware.name, DeviceSoftware.publisher, DeviceSoftware.resolved_by, func.max(cast(DeviceSoftware.cpe, String)).label("cpe"),
                   func.count(distinct(DeviceSoftware.device_id)).label("devices"))
            .where(DeviceSoftware.resolved_by.in_(["heuristic", "unresolved"]))
            .group_by(DeviceSoftware.name, DeviceSoftware.publisher, DeviceSoftware.resolved_by)
            .order_by(DeviceSoftware.resolved_by, func.count(distinct(DeviceSoftware.device_id)).desc(), DeviceSoftware.name)
        )
        rows = []
        for r in s.execute(q):
            d = r._asdict()
            d["cpe"] = [":".join(p) for p in json.loads(d["cpe"] or "[]")]
            rows.append(d)
        return render(request, "software.html", user, rows=rows)


# --- admin ---------------------------------------------------------------------------------


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: str = Depends(auth.current_user), error: str | None = None):
    with session_scope() as s:
        clients = s.scalars(select(Client).order_by(Client.name)).all()
        sites = s.scalars(select(Site).order_by(Site.name)).all()
        counts = dict(s.execute(select(Device.site_id, func.count()).group_by(Device.site_id)).all())
        sites = sorted(sites, key=lambda x: ({c.id: c.name for c in clients}[x.client_id].lower(), x.name.lower()))
        return render(request, "admin.html", user, clients=clients, sites=sites, counts=counts, error=error,
                      client_names={c.id: c.name for c in clients})


@router.post("/admin/clients")
def add_client(request: Request, name: str = Form(..., min_length=1, max_length=200), user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    try:
        with session_scope() as s:
            tenants.create_client(s, name)
    except IntegrityError:
        return RedirectResponse("/admin?error=" + quote(f"A client named {name} already exists."), 303)
    return RedirectResponse("/admin", 303)


@router.post("/admin/sites", response_class=HTMLResponse)
def add_site(request: Request, client_id: int = Form(...), name: str = Form(..., min_length=1, max_length=200), wua_check: bool = Form(False),
             user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    try:
        with session_scope() as s:
            client = s.get(Client, client_id) or _404()
            site, key = tenants.create_site(s, client, name, wua_check=wua_check)
            ctx = {"site": site, "client": client, "key": key, "server_url": str(request.base_url).rstrip("/")}
    except IntegrityError:
        return RedirectResponse("/admin?error=" + quote(f"That client already has a site named {name}."), 303)
    return render(request, "key.html", user, **ctx)


@router.post("/admin/sites/{site_id}/rotate", response_class=HTMLResponse)
def rotate_key(request: Request, site_id: int, user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        site = s.get(Site, site_id) or _404()
        key = tenants.rotate_site_key(s, site)
        return render(request, "key.html", user, site=site, client=s.get(Client, site.client_id), key=key, server_url=str(request.base_url).rstrip("/"), rotated=True)


@router.post("/admin/sites/{site_id}/wua")
def toggle_wua(request: Request, site_id: int, user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        site = s.get(Site, site_id) or _404()
        site.wua_check = not site.wua_check
    return RedirectResponse("/admin", 303)


def _404():
    raise HTTPException(404, "not found")
