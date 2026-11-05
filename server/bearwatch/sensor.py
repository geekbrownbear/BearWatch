"""Sensor mode: one enrolled PC per site scans its own network.

The technician picks the sensor PC for a site (admin page or `bearwatch site sensor`). Its
heartbeat then carries a `sensor` block, and every few hours the agent scans the PC's local
subnets (ping, ARP, names, common ports, and Proton's non-destructive configuration checks)
and uploads what it found to POST /api/agent/sensor.

The server keeps one NetworkHost row per thing on the network and links it to a managed PC when
the MAC (or failing that, the name) matches. What is left is the unmanaged list. A host first
seen after the site's baseline scan is "new" for a week, until a technician marks it as known
or an agent is installed on it. Configuration issues stay open until a scan reaches the host
again and the check passes; a host that is simply switched off keeps its issues.
"""

import re
from datetime import datetime, timedelta
from typing import Annotated

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .intel.common import utcnow
from .models import Device, NetworkHost, NetworkIssue, Site

NEW_FOR = timedelta(days=7)
MAC_RE = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"


# --- what the agent sends --------------------------------------------------------------------


class Names(BaseModel):
    dns: str | None = Field(default=None, max_length=255)
    netbios: str | None = Field(default=None, max_length=255)
    mdns: str | None = Field(default=None, max_length=255)
    upnp: str | None = Field(default=None, max_length=255)


class Port(BaseModel):
    port: int = Field(ge=1, le=65535)
    service: str | None = Field(default=None, max_length=255)
    banner: str | None = Field(default=None, max_length=300)


class Issue(BaseModel):
    id: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=0, le=65535)
    title: str = Field(min_length=1, max_length=200)
    cvss: float | None = Field(default=None, ge=0, le=10)
    evidence: str | None = Field(default=None, max_length=500)
    solution: str | None = Field(default=None, max_length=1000)


class Host(BaseModel):
    ip: str = Field(min_length=7, max_length=64)
    mac: str | None = Field(default=None, max_length=64)
    vendor: str | None = Field(default=None, max_length=255)
    names: Names = Names()
    workgroup: str | None = Field(default=None, max_length=255)
    rtt_ms: float | None = None
    ports: list[Port] = Field(default=[], max_length=200)
    issues: list[Issue] = Field(default=[], max_length=50)
    # Ports where a check could not finish (timeout, refused, garbled reply). Issues there stay
    # open: no answer is not evidence of a fix.
    unchecked_ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default=[], max_length=200)

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower().replace("-", ":")
        if not re.match(MAC_RE, v) or v == "00:00:00:00:00:00":
            return None  # unusable, not fatal: the host is still worth keeping by IP
        return v


class Network(BaseModel):
    interface: str | None = Field(default=None, max_length=255)
    cidr: str = Field(max_length=64)
    address: str | None = Field(default=None, max_length=64)
    gateway: str | None = Field(default=None, max_length=64)


class Report(BaseModel):
    agent_version: str = Field(max_length=32)
    started_at: datetime
    duration_ms: int = Field(ge=0)
    networks: list[Network] = Field(default=[], max_length=4)
    hosts: list[Host] = Field(default=[], max_length=4096)


# --- storing a scan -------------------------------------------------------------------------


def host_key(h: Host) -> str:
    return f"mac:{h.mac}" if h.mac else f"ip:{h.ip}"


def best_name(n: Names) -> str | None:
    """NetBIOS and mDNS names are what people call the device; DNS often has a suffix."""
    for v in (n.netbios, n.mdns, n.upnp, n.dns):
        if v and v.strip():
            return v.strip()
    return None


def _short(name: str | None) -> str | None:
    if not name:
        return None
    return name.strip().split(".")[0].lower() or None


def _managed(s: Session, site: Site) -> tuple[dict[str, int], dict[str, int]]:
    """MAC -> device and short hostname -> device, over the whole client: one office LAN often
    holds PCs enrolled under more than one site."""
    by_mac: dict[str, int] = {}
    by_name: dict[str, int] = {}
    q = select(Device).join(Site, Site.id == Device.site_id).where(Site.client_id == site.client_id)
    for d in s.scalars(q):
        for m in d.macs or []:
            by_mac.setdefault(str(m).lower(), d.id)
        if (k := _short(d.hostname)) is not None:
            by_name.setdefault(k, d.id)
    return by_mac, by_name


def match_device(h: NetworkHost, by_mac: dict[str, int], by_name: dict[str, int]) -> int | None:
    if h.mac and h.mac in by_mac:
        return by_mac[h.mac]
    names = h.names or {}
    for v in (names.get("netbios"), names.get("dns"), names.get("mdns")):
        if (k := _short(v)) is not None and k in by_name:
            return by_name[k]
    return None


def store(s: Session, site: Site, rep: Report) -> int:
    """Record one scan. Returns the number of hosts in it."""
    now = utcnow()
    existing = {h.key: h for h in s.scalars(select(NetworkHost).where(NetworkHost.site_id == site.id))}
    by_mac, by_name = _managed(s, site)
    seen: set[str] = set()
    for h in rep.hosts:
        key = host_key(h)
        if key in seen:  # one host answering on two of the sensor's networks
            continue
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = NetworkHost(site_id=site.id, key=key, first_seen=now, known=False)
            s.add(row)
            existing[key] = row
        row.mac, row.ip, row.vendor, row.workgroup = h.mac, h.ip, h.vendor, h.workgroup
        row.names = h.names.model_dump()
        row.name = best_name(h.names)
        row.ports = [p.model_dump() for p in sorted(h.ports, key=lambda p: p.port)]
        row.last_seen = now
        row.device_id = match_device(row, by_mac, by_name)
        s.flush()
        _issues(s, row, h.issues, now, set(h.unchecked_ports))
    site.sensor_scan_at = now
    if site.sensor_first_scan_at is None:
        site.sensor_first_scan_at = now
    s.flush()
    return len(seen)


def _issues(s: Session, host: NetworkHost, found: list[Issue], now: datetime, unchecked: set[int] = frozenset()) -> None:
    """The host was reached in this scan. An open issue is fixed only if its check finished on
    that port and found nothing; a port the agent could not check keeps its issues open."""
    rows = {(i.check_id, i.port): i for i in s.scalars(select(NetworkIssue).where(NetworkIssue.host_id == host.id))}
    current: set[tuple[str, int]] = set()
    for f in found:
        k = (f.id, f.port)
        if k in current:
            continue
        current.add(k)
        row = rows.get(k)
        if row is None:
            row = NetworkIssue(host_id=host.id, check_id=f.id, port=f.port, first_seen=now)
            s.add(row)
        elif row.status == "fixed":
            row.first_seen = now  # came back: its age starts again
        row.title, row.cvss, row.evidence, row.solution = f.title, f.cvss, f.evidence, f.solution
        row.status, row.last_seen, row.fixed_at = "open", now, None
    for k, row in rows.items():
        if k not in current and row.status == "open" and row.port not in unchecked:
            row.status, row.fixed_at = "fixed", now


def link_device(s: Session, dev: Device) -> None:
    """A PC reported its MACs: claim the hosts the sensor already found with them."""
    macs = [str(m).lower() for m in dev.macs or []]
    if not macs:
        return
    site = s.get(Site, dev.site_id)
    if site is None:
        return
    sites = select(Site.id).where(Site.client_id == site.client_id)
    s.execute(update(NetworkHost).where(NetworkHost.site_id.in_(sites), NetworkHost.mac.in_(macs)).values(device_id=dev.id))


# --- reading ---------------------------------------------------------------------------------


def is_new(h: NetworkHost, site: Site, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return (
        not h.known
        and h.device_id is None
        and site.sensor_first_scan_at is not None
        and h.first_seen > site.sensor_first_scan_at
        and now - h.first_seen < NEW_FOR
    )


def sensor_device(s: Session, site: Site) -> Device | None:
    """The site's sensor PC, if it still exists and still belongs to the site."""
    if site.sensor_device_id is None:
        return None
    dev = s.get(Device, site.sensor_device_id)
    return dev if dev is not None and dev.site_id == site.id else None


def sensor_silent(site: Site, interval_minutes: int, now: datetime | None = None) -> bool:
    """No scan for two intervals plus an hour: the sensor PC is off, or scanning fails. Before
    the first scan the pages say "waiting for the first scan" instead."""
    if site.sensor_device_id is None or site.sensor_scan_at is None:
        return False
    now = now or utcnow()
    return now - site.sensor_scan_at > timedelta(minutes=2 * interval_minutes + 60)


def is_issue(cvss: float | None) -> bool:
    """Checks scored 0 are notes, not problems ("RDP reachable", "software version detected").
    They are stored and shown with the host, but never counted as issues."""
    return cvss is None or cvss > 0


def issue_clause():
    """SQL version of is_issue."""
    return or_(NetworkIssue.cvss.is_(None), NetworkIssue.cvss > 0)


def severity(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss <= 0:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
