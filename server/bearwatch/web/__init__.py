"""Server-rendered dashboard. No JavaScript framework; every page is one query-backed template.

Findings are shown grouped by fix: one row per KB or app update, with the devices that need it
and the CVEs it closes, because that is the unit a technician actually works in. Fixes and
devices sort by risk score (scoring.py), and every score shows how it was reached.
"""

import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, and_, case, cast, distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import __version__, auth, halo, lifecycle, posture, report, scoring, sensor, tenants
from ..config import get_settings
from ..db import session_scope
from ..intel.common import utcnow
from ..models import (Client, Device, DeviceSoftware, Finding, FindingEvent, FindingException, NetworkHost, NetworkIssue, Site,
                      SyncState, WuaUpdate)

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


def deadline(f: Finding) -> tuple[str, str]:
    """(css class, text) for an open finding's fix deadline."""
    if f.exception_id is not None:
        return "muted", "Paused by exception"
    if f.due_at is None:
        return "muted", "-"
    days = (f.due_at - utcnow()).total_seconds() / 86400
    if days < 0:
        n = max(1, int(-days))
        return "bad", f"Overdue {n} day{'s' if n != 1 else ''}"
    n = int(days)
    return ("warn" if n < 7 else ""), ("Due today" if n == 0 else f"Due in {n} day{'s' if n != 1 else ''}")


TIER_LABEL = {1: "Exploited", 2: "Exploit code", 3: "Likely", 4: "No signal"}
# Posture severities borrow the tier badge colors: critical is as red as "exploited".
SEVERITY_CLASS = {"critical": "t1", "high": "t2", "medium": "t3", "low": "t4"}
SEVERITY_ORDER = {s: i for i, s in enumerate(posture.SEVERITIES)}


def posture_rule(fix_key: str) -> posture.Rule | None:
    """The rule behind a "posture:<id>" fix key, or None (not posture, or a rule since removed)."""
    return posture.rule(fix_key.removeprefix("posture:")) if fix_key.startswith("posture:") else None


templates.env.globals.update(ago=ago, health=health, deadline=deadline, tier_label=TIER_LABEL, version=__version__, quote=quote,
                             importance_label=scoring.IMPORTANCE_LABEL, reasons=scoring.REASONS, posture_rule=posture_rule,
                             severity_class=SEVERITY_CLASS)
templates.env.filters["pct"] = lambda v: "-" if v is None else f"{v * 100:.1f}%"
templates.env.filters["score"] = lambda v: "-" if v is None else f"{v:.1f}"
templates.env.filters["risk"] = lambda v: "-" if v is None else f"{v:.0f}"


def render(request: Request, name: str, user: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, {"user": user, **ctx})


# --- queries -------------------------------------------------------------------------------


def fix_rows(s: Session, client_id: int | None = None, device_id: int | None = None, limit: int | None = None) -> list[dict]:
    """Open findings grouped by fix, highest risk first."""
    now = utcnow()
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
            func.max(Finding.risk).label("risk"),
            func.count(distinct(case((scoring.overdue_clause(now), Finding.device_id)))).label("overdue"),
        )
        .join(Device, Device.id == Finding.device_id)
        .join(Site, Site.id == Device.site_id)
        .where(Finding.status == "open")
        .group_by(Finding.fix_key)
        .order_by(func.max(Finding.risk).desc(), func.min(Finding.exploit_tier), func.count(distinct(Finding.device_id)).desc(),
                  func.count(distinct(Finding.cve_id)).desc(), Finding.fix_key)
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
        select(Device, Site, open_count.label("open"), func.count(case((Finding.exploit_tier == 1, Finding.id))).label("exploited"),
               func.max(Finding.risk).label("risk"), func.count(case((scoring.overdue_clause(utcnow()), Finding.id))).label("overdue"))
        .join(Site, Site.id == Device.site_id)
        .outerjoin(Finding, and_(Finding.device_id == Device.id, Finding.status == "open"))
        .group_by(Device.id, Site.id)
        .order_by(func.max(Finding.risk).desc().nulls_last(), open_count.desc(), Device.hostname)
    )
    if client_id is not None:
        q = q.where(Site.client_id == client_id)
    return [{"device": d, "site": site, "open": n, "exploited": x, "risk": r, "overdue": o} for d, site, n, x, r, o in s.execute(q)]


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
                "overdue": sum(d["overdue"] for d in devs),
                "top_fix": top[0] if top else None,
                **network_counts(s, client_id=c.id),
            }
        )
    return rows


RECENT = timedelta(days=30)  # hosts not seen for longer drop out of the counts (still listed)


def network_counts(s: Session, client_id: int | None = None, site_id: int | None = None) -> dict:
    """Hosts the sensors saw in the last 30 days: unmanaged, new, and open issues."""
    now = utcnow()
    q = select(NetworkHost, Site).join(Site, Site.id == NetworkHost.site_id).where(NetworkHost.last_seen >= now - RECENT)
    iq = (select(func.count(NetworkIssue.id)).join(NetworkHost, NetworkHost.id == NetworkIssue.host_id)
          .join(Site, Site.id == NetworkHost.site_id).where(NetworkIssue.status == "open", sensor.issue_clause()))
    if client_id is not None:
        q, iq = q.where(Site.client_id == client_id), iq.where(Site.client_id == client_id)
    if site_id is not None:
        q, iq = q.where(Site.id == site_id), iq.where(Site.id == site_id)
    hosts = s.execute(q).all()
    return {
        "net_hosts": len(hosts),
        "net_unmanaged": sum(1 for h, _ in hosts if h.device_id is None),
        "net_new": sum(1 for h, site in hosts if sensor.is_new(h, site, now)),
        "net_issues": s.scalar(iq) or 0,
    }


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
        feeds = s.scalars(select(SyncState).where(SyncState.source != posture.SYNC_KEY).order_by(SyncState.source)).all()
        return render(request, "overview.html", user, clients=clients, fixes=fixes, feeds=feeds, totals={
            "devices": sum(c["devices"] for c in clients),
            "silent": sum(c["silent"] for c in clients),
            "open": sum(c["open"] for c in clients),
            "exploited": sum(c["exploited"] for c in clients),
            "overdue": sum(c["overdue"] for c in clients),
            "net_new": sum(c["net_new"] for c in clients),
            "net_issues": sum(c["net_issues"] for c in clients),
        })


@router.get("/clients/{client_id}", response_class=HTMLResponse)
def client_page(request: Request, client_id: int, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        client = s.get(Client, client_id) or _404()
        sites = s.scalars(select(Site).where(Site.client_id == client_id).order_by(Site.name)).all()
        interval = get_settings().sensor_interval_minutes
        net = {site.id: {**network_counts(s, site_id=site.id), "sensor": sensor.sensor_device(s, site),
                         "silent": sensor.sensor_silent(site, interval)} for site in sites}
        return render(request, "client.html", user, client=client, sites=sites, fixes=fix_rows(s, client_id=client_id),
                      devices=device_rows(s, client_id), net=net, halo_on=halo.configured(), halo_dry=get_settings().halo_dry_run,
                      halo_open=halo.open_count(s, client_id))


@router.post("/clients/{client_id}/halo")
def set_halo_client(request: Request, client_id: int, halo_client_id: str = Form(""), user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    value = halo_client_id.strip()
    if value and not value.isdigit():
        raise HTTPException(400, "the Halo client id is a number")
    with session_scope() as s:
        client = s.get(Client, client_id) or _404()
        client.halo_client_id = int(value) if value else None
    return RedirectResponse(f"/clients/{client_id}", 303)


@router.get("/fix", response_class=HTMLResponse)
def fix_page(request: Request, key: str, client: int | None = None, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        q = select(Finding, Device).join(Device, Device.id == Finding.device_id).join(Site, Site.id == Device.site_id).where(Finding.fix_key == key, Finding.status == "open")
        if client is not None:
            q = q.where(Site.client_id == client)
        rows = s.execute(q.order_by(Finding.exploit_tier, Finding.epss.desc().nulls_last(), Finding.cve_id)).all()
        if not rows:
            return render(request, "fix.html", user, key=key, label=None, devices=[], cves=[], client=s.get(Client, client) if client else None,
                          rule=posture_rule(key))
        devices: dict[int, dict] = {}
        cves: dict[str, Finding] = {}
        for f, d in rows:
            devices.setdefault(d.id, {"device": d, "cves": 0, "version": f.subject_version})["cves"] += 1
            cves.setdefault(f.cve_id, f)
        return render(request, "fix.html", user, key=key, label=rows[0][0].fix_label, devices=sorted(devices.values(), key=lambda x: x["device"].hostname.lower()),
                      cves=list(cves.values()), client=s.get(Client, client) if client else None, rule=posture_rule(key))


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(request: Request, device_id: int, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        dev = s.get(Device, device_id) or _404()
        site = s.get(Site, dev.site_id)
        client = s.get(Client, site.client_id)
        open_findings = s.scalars(select(Finding).where(Finding.device_id == device_id, Finding.status == "open")
                                  .order_by(Finding.risk.desc(), Finding.exploit_tier, Finding.epss.desc().nulls_last(), Finding.cve_id)).all()
        held = {f.exception_id for f in open_findings if f.exception_id}
        excs = {e.id: e for e in s.scalars(select(FindingException).where(FindingException.id.in_(held)))} if held else {}
        why = {f.id: scoring.breakdown(f, dev, excs.get(f.exception_id)) for f in open_findings}
        by_fix: dict[str, list[Finding]] = {}
        for f in open_findings:
            by_fix.setdefault(f.fix_key, []).append(f)
        fixes = [r for r in fix_rows(s, device_id=device_id)]
        software = s.scalars(select(DeviceSoftware).where(DeviceSoftware.device_id == device_id).order_by(func.lower(DeviceSoftware.name))).all()
        wua = s.scalars(select(WuaUpdate).where(WuaUpdate.device_id == device_id).order_by(WuaUpdate.title)).all()
        events = s.execute(select(FindingEvent, Finding).join(Finding, Finding.id == FindingEvent.finding_id)
                           .where(FindingEvent.device_id == device_id).order_by(FindingEvent.at.desc(), FindingEvent.id.desc()).limit(40)).all()
        net_hosts = s.scalars(select(NetworkHost).where(NetworkHost.device_id == device_id).order_by(NetworkHost.last_seen.desc())).all()
        net_issues = s.scalars(select(NetworkIssue).where(NetworkIssue.host_id.in_([h.id for h in net_hosts]), NetworkIssue.status == "open", sensor.issue_clause())
                               .order_by(NetworkIssue.cvss.desc().nulls_last())).all() if net_hosts else []
        return render(request, "device.html", user, dev=dev, site=site, client=client, fixes=fixes, by_fix=by_fix, software=software,
                      wua=wua, cross=_cross_check(dev, open_findings, wua), events=events, why=why, excs=excs,
                      importance=scoring.importance(dev), settings=_settings(dev), net_hosts=net_hosts, net_issues=net_issues,
                      is_sensor=site.sensor_device_id == dev.id, severity_of=sensor.severity,
                      support=lifecycle.support(dev.os_build, dev.os_caption, dev.is_server) if dev.os_build else None)


def _settings(dev: Device) -> list[posture.Result] | None:
    """Every posture rule for this device, failures first. None until the agent reports any."""
    if not dev.posture:
        return None
    results = posture.evaluate(posture.ruleset(), dev.posture.get("values") or {}, dev.is_server, posture.build_number(dev.os_build))
    status_order = {"fail": 0, "unknown": 1, "pass": 2}
    return sorted(results, key=lambda r: (status_order[r.status], SEVERITY_ORDER[r.rule.severity], r.rule.title))


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


@router.post("/devices/{device_id}/settings")
def device_settings(request: Request, device_id: int, criticality: str = Form(""), internet_facing: bool = Form(False),
                    user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        dev = s.get(Device, device_id) or _404()
        dev.criticality = int(criticality) if criticality in {"1", "2", "3", "4", "5"} else None
        dev.internet_facing = internet_facing
        scoring.rescore(s, dev)
    return RedirectResponse(f"/devices/{device_id}", 303)


# --- exceptions ----------------------------------------------------------------------------

# CVE numbers have 4 or more digits with no fixed maximum. The cap only keeps the id inside
# the String(32) cve_id columns ("CVE-YYYY-" is 9 characters).
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,23}$")


@dataclass
class Scope:
    client: Client
    device: Device | None
    fix_key: str | None
    fix_label: str | None
    cve_id: str | None
    matching: int


def _scope(s: Session, client_id: int | None, device_id: int | None, fix_key: str | None, cve_id: str | None) -> Scope:
    """What an exception would cover. Raises 404 or 400 for anything that does not add up."""
    dev = None
    if device_id is not None:
        dev = s.get(Device, device_id) or _404()
        owner = s.scalar(select(Site.client_id).where(Site.id == dev.site_id))
        if client_id is not None and client_id != owner:
            raise HTTPException(400, "that device belongs to another client")
        client_id = owner
    client = s.get(Client, client_id) if client_id is not None else None
    if client is None:
        _404()
    fix_key = (fix_key or "").strip() or None
    cve_id = (cve_id or "").strip().upper() or None
    if not fix_key and not cve_id:
        raise HTTPException(400, "an exception needs a fix, a CVE, or both")
    if cve_id and not CVE_RE.match(cve_id):
        raise HTTPException(400, "not a CVE id")
    if fix_key and len(fix_key) > 220:
        raise HTTPException(400, "fix key too long")
    q = (select(func.count(Finding.id), func.max(Finding.fix_label)).join(Device, Device.id == Finding.device_id)
         .join(Site, Site.id == Device.site_id).where(Site.client_id == client.id, Finding.status == "open"))
    if dev:
        q = q.where(Finding.device_id == dev.id)
    if fix_key:
        q = q.where(Finding.fix_key == fix_key)
    if cve_id:
        q = q.where(Finding.cve_id == cve_id)
    n, label = s.execute(q).one()
    return Scope(client, dev, fix_key, label if fix_key else None, cve_id, n)


@router.get("/exceptions", response_class=HTMLResponse)
def exceptions_page(request: Request, client: int | None = None, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        today = utcnow().date()
        q = (select(FindingException, Client, Device).join(Client, Client.id == FindingException.client_id)
             .outerjoin(Device, Device.id == FindingException.device_id))
        if client is not None:
            q = q.where(FindingException.client_id == client)
        rows = s.execute(q.order_by(FindingException.expires_on, FindingException.id.desc())).all()
        held = dict(s.execute(select(Finding.exception_id, func.count()).where(Finding.status == "open", Finding.exception_id.is_not(None))
                              .group_by(Finding.exception_id)).all())
        active = [r for r in rows if scoring.is_active(r[0], today)]
        ended = [r for r in rows if not scoring.is_active(r[0], today)]
        ended.sort(key=lambda r: r[0].revoked_at or datetime.combine(r[0].expires_on, datetime.max.time()), reverse=True)
        return render(request, "exceptions.html", user, active=active, ended=ended[:100], held=held, today=today,
                      client=s.get(Client, client) if client is not None else None)


@router.get("/exceptions/new", response_class=HTMLResponse)
def exception_form(request: Request, client: int | None = None, device: int | None = None, fix: str | None = None, cve: str | None = None,
                   error: str | None = None, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        today = utcnow().date()
        return render(request, "exception_new.html", user, scope=_scope(s, client, device, fix, cve), error=error,
                      default_expiry=today + timedelta(days=90), max_expiry=today + timedelta(days=scoring.MAX_EXCEPTION_DAYS), today=today)


@router.post("/exceptions")
def create_exception(request: Request, reason: str = Form(""), note: str = Form("", max_length=2000), expires_on: str = Form(""),
                     client: int | None = Form(None), device: int | None = Form(None), fix: str = Form(""), cve: str = Form(""),
                     user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    today = utcnow().date()
    try:
        until = date.fromisoformat(expires_on)
    except ValueError:
        until = None
    error = None
    if reason not in scoring.REASONS:
        error = "Pick a reason."
    elif not note.strip():
        error = "Add a note that explains the decision."
    elif until is None or not today <= until <= today + timedelta(days=scoring.MAX_EXCEPTION_DAYS):
        error = f"The end date must be between today and {scoring.MAX_EXCEPTION_DAYS} days from now."
    with session_scope() as s:
        sc = _scope(s, client, device, fix, cve)
        if error:
            params = {"client": sc.client.id, "device": sc.device.id if sc.device else None, "fix": sc.fix_key, "cve": sc.cve_id, "error": error}
            return RedirectResponse("/exceptions/new?" + "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items() if v is not None), 303)
        s.add(FindingException(client_id=sc.client.id, device_id=sc.device.id if sc.device else None, fix_key=sc.fix_key, cve_id=sc.cve_id,
                               reason=reason, note=note.strip(), expires_on=until, created_by=user[:200], created_at=utcnow()))
        s.flush()
        scoring.rescore_client(s, sc.client.id, sc.device.id if sc.device else None)
        target = f"/devices/{sc.device.id}" if sc.device else f"/exceptions?client={sc.client.id}"
    return RedirectResponse(target, 303)


@router.post("/exceptions/{exc_id}/revoke")
def revoke_exception(request: Request, exc_id: int, user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        exc = s.get(FindingException, exc_id) or _404()
        if exc.revoked_at is None:
            exc.revoked_at, exc.revoked_by = utcnow(), user[:200]
            s.flush()
            scoring.rescore_client(s, exc.client_id, exc.device_id)
        client_id = exc.client_id
    return RedirectResponse(f"/exceptions?client={client_id}", 303)


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
        site_devices: dict[int, list[Device]] = {}
        for d in s.scalars(select(Device).order_by(func.lower(Device.hostname))):
            site_devices.setdefault(d.site_id, []).append(d)
        return render(request, "admin.html", user, clients=clients, sites=sites, counts=counts, error=error,
                      client_names={c.id: c.name for c in clients}, site_devices=site_devices)


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


@router.post("/admin/sites/{site_id}/sensor")
def set_sensor(request: Request, site_id: int, device_id: str = Form(""), user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        site = s.get(Site, site_id) or _404()
        dev = None
        if device_id:
            dev = (s.get(Device, int(device_id)) if device_id.isdigit() else None) or _404()
        try:
            tenants.set_sensor(s, site, dev)
        except ValueError as e:
            return RedirectResponse("/admin?error=" + quote(str(e)), 303)
    return RedirectResponse("/admin", 303)


@router.get("/sites/{site_id}/network", response_class=HTMLResponse)
def network_page(request: Request, site_id: int, show: str = "recent", user: str = Depends(auth.current_user)):
    with session_scope() as s:
        site = s.get(Site, site_id) or _404()
        client = s.get(Client, site.client_id)
        now, interval = utcnow(), get_settings().sensor_interval_minutes
        q = select(NetworkHost).where(NetworkHost.site_id == site_id)
        if show != "all":
            q = q.where(NetworkHost.last_seen >= now - RECENT)
        hosts = s.scalars(q).all()
        issues = s.execute(select(NetworkIssue, NetworkHost).join(NetworkHost, NetworkHost.id == NetworkIssue.host_id)
                           .where(NetworkHost.site_id == site_id, NetworkIssue.status == "open", sensor.issue_clause())
                           .order_by(NetworkIssue.cvss.desc().nulls_last(), NetworkHost.ip)).all()
        open_by_host: dict[int, int] = {}
        for _, h in issues:
            open_by_host[h.id] = open_by_host.get(h.id, 0) + 1
        notes: dict[int, list[str]] = {}
        for i in s.scalars(select(NetworkIssue).join(NetworkHost, NetworkHost.id == NetworkIssue.host_id)
                           .where(NetworkHost.site_id == site_id, NetworkIssue.status == "open", NetworkIssue.cvss <= 0)
                           .order_by(NetworkIssue.title)):
            if i.title not in notes.setdefault(i.host_id, []):
                notes[i.host_id].append(i.title)
        ids = [h.device_id for h in hosts if h.device_id]
        devices = {d.id: d for d in s.scalars(select(Device).where(Device.id.in_(ids)))} if ids else {}
        rows = [{"host": h, "new": sensor.is_new(h, site, now), "device": devices.get(h.device_id), "issues": open_by_host.get(h.id, 0),
                 "notes": notes.get(h.id, []), "online": site.sensor_scan_at is not None and h.last_seen >= site.sensor_scan_at} for h in hosts]
        # New first, then unmanaged, then managed; by address within each.
        rows.sort(key=lambda r: (not r["new"], r["device"] is not None, _ip_key(r["host"].ip)))
        return render(request, "network.html", user, site=site, client=client, rows=rows, issues=issues, show=show,
                      sensor_dev=sensor.sensor_device(s, site), silent=sensor.sensor_silent(site, interval),
                      counts=network_counts(s, site_id=site_id), severity_of=sensor.severity, interval=interval)


def _ip_key(ip: str) -> tuple:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, *(int(p) for p in parts))
    return (1, ip)


@router.post("/network/hosts/{host_id}/known")
def toggle_known(request: Request, host_id: int, user: str = Depends(auth.current_user)):
    auth.check_origin(request)
    with session_scope() as s:
        h = s.get(NetworkHost, host_id) or _404()
        h.known = not h.known
        site_id = h.site_id
    return RedirectResponse(f"/sites/{site_id}/network", 303)


def _report_month(month: str | None) -> date:
    if not month:
        return report.previous_month()
    try:
        return datetime.strptime(month, "%Y-%m").date()
    except ValueError:
        raise HTTPException(400, "month must look like 2026-10") from None


@router.get("/clients/{client_id}/report", response_class=HTMLResponse)
def report_preview(request: Request, client_id: int, month: str | None = None, user: str = Depends(auth.current_user)):
    with session_scope() as s:
        s.get(Client, client_id) or _404()
        r = report.build(s, client_id, _report_month(month))
        return HTMLResponse(report.render_html(r, screen=True, static="/static"))


@router.get("/clients/{client_id}/report.pdf")
def report_pdf(request: Request, client_id: int, month: str | None = None, user: str = Depends(auth.current_user)):
    if not report.pdf_available():
        raise HTTPException(503, "PDF rendering is not installed on this server (WeasyPrint); use the HTML preview")
    with session_scope() as s:
        client = s.get(Client, client_id) or _404()
        r = report.build(s, client_id, _report_month(month))
        pdf = report.render_pdf(r)
        name = re.sub(r"[^A-Za-z0-9]+", "-", client.name).strip("-") or "client"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}-security-report-{r.month:%Y-%m}.pdf"'})


def _404():
    raise HTTPException(404, "not found")
