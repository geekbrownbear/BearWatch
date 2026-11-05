"""Clients, sites, devices and the secrets agents use.

Enrollment keys (one per site) and device tokens (one per device) are random 32-byte values.
Only their SHA-256 is stored, so a database copy cannot be used to impersonate an agent.
"""

import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from .intel.common import utcnow
from .models import Client, Device, Site

ENROLL_PREFIX = "bwe_"
DEVICE_PREFIX = "bwd_"


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _new_secret(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def create_client(s: Session, name: str) -> Client:
    c = Client(name=name.strip(), created_at=utcnow())
    s.add(c)
    s.flush()
    return c


def create_site(s: Session, client: Client, name: str, wua_check: bool = False) -> tuple[Site, str]:
    """Returns the site and its enrollment key. The key is shown once and never stored."""
    key = _new_secret(ENROLL_PREFIX)
    site = Site(client_id=client.id, name=name.strip(), enroll_key_hash=digest(key), enroll_key_hint=key[:8], wua_check=wua_check, created_at=utcnow())
    s.add(site)
    s.flush()
    return site, key


def rotate_site_key(s: Session, site: Site) -> str:
    """New enrollment key. Already enrolled devices keep working; the old key stops enrolling."""
    key = _new_secret(ENROLL_PREFIX)
    site.enroll_key_hash, site.enroll_key_hint = digest(key), key[:8]
    s.flush()
    return key


def site_for_key(s: Session, key: str) -> Site | None:
    if not key.startswith(ENROLL_PREFIX):
        return None
    return s.scalar(select(Site).where(Site.enroll_key_hash == digest(key)))


def enroll(s: Session, site: Site, machine_guid: str, hostname: str, agent_version: str | None) -> tuple[Device, str]:
    """Register a device, or re-register it (reinstall, reimage) and issue a fresh token.

    The same Windows MachineGuid in the same site is the same device, so its history and
    findings carry over.
    """
    token = _new_secret(DEVICE_PREFIX)
    now = utcnow()
    dev = s.scalar(select(Device).where(Device.site_id == site.id, Device.machine_guid == machine_guid))
    if dev is None:
        dev = Device(site_id=site.id, machine_guid=machine_guid, enrolled_at=now, is_server=False, server_core=False, needs_match=False, rescan_requested=False)
        s.add(dev)
    dev.hostname, dev.agent_version, dev.token_hash, dev.last_seen = hostname, agent_version, digest(token), now
    s.flush()
    return dev, token


def device_for_token(s: Session, token: str) -> Device | None:
    if not token.startswith(DEVICE_PREFIX):
        return None
    return s.scalar(select(Device).where(Device.token_hash == digest(token)))


def set_sensor(s: Session, site: Site, dev: Device | None) -> None:
    """Make `dev` the PC that scans this site's network, or turn sensor mode off with None.

    A new sensor may sit on another subnet, so its first scan becomes the new baseline: hosts it
    finds then are not flagged as new. Hosts and issues found so far stay.
    """
    if dev is not None and dev.site_id != site.id:
        raise ValueError(f"{dev.hostname} is enrolled in another site")
    new_id = dev.id if dev is not None else None
    if new_id != site.sensor_device_id:
        site.sensor_device_id = new_id
        site.sensor_first_scan_at = None
