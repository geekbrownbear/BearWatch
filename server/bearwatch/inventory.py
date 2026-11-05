"""What an agent sends, and how it is stored.

The agent collects every few hours but uploads only when its inventory hash changes, so an
unchanged PC costs one small heartbeat. Storing an inventory replaces the device's previous
software, KB and Windows Update lists and queues the device for matching in the worker.
"""

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import delete
from sqlalchemy.orm import Session

from . import posture, sensor
from .intel.common import utcnow
from .match import windows
from .models import Device, DeviceKb, DeviceSoftware, WuaUpdate

S = dict(max_length=400)


class OsInfo(BaseModel):
    caption: str = Field(default="", max_length=200)  # e.g. "Windows 11 Pro 23H2"
    build: str = Field(pattern=r"^\d+\.\d+\.\d+\.\d+$")  # 10.0.22631.4317 (UBR included)
    arch: str = Field(default="x64", pattern=r"^(x64|x86|arm64)$")
    server: bool = False
    server_core: bool = False
    reboot_pending: bool = False


class Program(BaseModel):
    name: str = Field(min_length=1, **S)
    version: str = Field(default="", max_length=120)
    publisher: str | None = Field(default=None, max_length=200)
    scope: str = Field(default="machine", pattern=r"^(machine|user)$")


class WuaEntry(BaseModel):
    kb: str | None = Field(default=None, max_length=16)
    title: str = Field(**S)
    severity: str | None = Field(default=None, max_length=16)
    is_security: bool = False
    cves: list[str] = Field(default=[], max_length=500)


class WuaResult(BaseModel):
    checked_at: datetime
    error: str | None = Field(default=None, max_length=1000)
    missing: list[WuaEntry] = Field(default=[], max_length=500)


class PostureReport(BaseModel):
    """The values the agent read for the posture rules with this hash (see posture.py)."""

    hash: str = Field(min_length=8, max_length=64)
    values: dict[Annotated[str, StringConstraints(max_length=posture.MAX_READ_LEN)], int | bool | Literal["set"] | None] = Field(
        default={}, max_length=posture.MAX_READS)


class Inventory(BaseModel):
    hash: str = Field(min_length=8, max_length=64)
    agent_version: str = Field(max_length=32)
    hostname: str = Field(min_length=1, max_length=255)
    os: OsInfo
    kbs: list[str] = Field(default=[], max_length=2000)
    pending_kbs: list[str] = Field(default=[], max_length=200)
    software: list[Program] = Field(default=[], max_length=5000)
    wua: WuaResult | None = None
    posture: PostureReport | None = None  # agents before 0.2.0 send none
    # Network adapter MACs, so sensor hosts can be matched to this PC. Agents before 0.3.0 send none.
    macs: list[Annotated[str, StringConstraints(max_length=64)]] = Field(default=[], max_length=64)


def store(s: Session, dev: Device, inv: Inventory) -> None:
    now = utcnow()
    dev.hostname, dev.agent_version, dev.inventory_hash = inv.hostname, inv.agent_version, inv.hash
    dev.os_caption, dev.os_build, dev.os_arch = inv.os.caption, inv.os.build, inv.os.arch
    dev.is_server, dev.server_core, dev.reboot_pending = inv.os.server, inv.os.server_core, inv.os.reboot_pending
    dev.os_product = windows.product_name(inv.os.build, inv.os.arch, inv.os.server, inv.os.server_core)
    dev.last_seen = dev.last_inventory_at = now
    dev.needs_match, dev.rescan_requested = True, False

    s.execute(delete(DeviceKb).where(DeviceKb.device_id == dev.id))
    kbs = {k.upper().removeprefix("KB").strip() for k in inv.kbs}
    s.add_all(DeviceKb(device_id=dev.id, kb=k) for k in sorted(kbs) if k.isdigit())
    pending = {k.upper().removeprefix("KB").strip() for k in inv.pending_kbs}
    dev.pending_kbs = sorted(k for k in pending - kbs if k.isdigit() and len(k) <= 10)

    s.execute(delete(DeviceSoftware).where(DeviceSoftware.device_id == dev.id))
    seen: set[tuple[str, str]] = set()
    for p in inv.software:
        key = (p.name.strip().lower(), p.version.strip())
        if key in seen:  # the same install often appears under both registry views
            continue
        seen.add(key)
        s.add(DeviceSoftware(device_id=dev.id, name=p.name.strip(), version=p.version.strip(), publisher=p.publisher, scope=p.scope, cpe=[]))

    if inv.wua is not None:
        dev.wua_checked_at, dev.wua_error = inv.wua.checked_at.replace(tzinfo=None), inv.wua.error
        s.execute(delete(WuaUpdate).where(WuaUpdate.device_id == dev.id))
        for w in inv.wua.missing:
            kb = (w.kb or "").upper().removeprefix("KB") or None
            s.add(WuaUpdate(device_id=dev.id, kb=kb, title=w.title, severity=w.severity, is_security=w.is_security, cves=[c.upper() for c in w.cves][:500]))

    if inv.posture is not None:
        # The agent enforces the same allowlist; anything outside it is dropped, not stored.
        values = {k: v for k, v in inv.posture.values.items() if posture.read_allowed(k)}
        dev.posture, dev.posture_at = {"hash": inv.posture.hash, "values": values}, now
    else:
        # An older agent took over (downgrade or reinstall): don't keep judging stale values.
        # Open posture findings stay open, since no data is not evidence of a fix.
        dev.posture, dev.posture_at = None, None

    macs = sorted({m.strip().lower().replace("-", ":") for m in inv.macs} - {"00:00:00:00:00:00"})
    dev.macs = [m for m in macs if re.match(sensor.MAC_RE, m)] or None
    s.flush()
    sensor.link_device(s, dev)
