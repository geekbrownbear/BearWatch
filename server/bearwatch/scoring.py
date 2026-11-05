"""Risk score, fix deadlines and exceptions for open findings (see docs/scoring.md).

risk = base(tier, cvss) x importance x exposure x exception

Every factor is kept small and explainable so the dashboard can show the sum next to the number.
`rescore` is the only writer of Finding.risk, due_at and exception_id. It runs after every
evaluation, after a device's settings change, and when an exception is added, revoked or lapses.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .intel.common import utcnow
from .models import Device, Finding, FindingException, Site

UNKNOWN_CVSS = 5.0  # no CVSS from NVD or MSRC: score it as a medium
EXPOSED = 1.2

IMPORTANCE = {1: 0.6, 2: 0.8, 3: 1.0, 4: 1.2, 5: 1.4}
IMPORTANCE_LABEL = {
    1: "Low (kiosk, lab PC)",
    2: "Below normal",
    3: "Normal (workstation)",
    4: "High (server, executive laptop)",
    5: "Critical (domain controller)",
}

# reason: (label, score factor). Only the first two lower the score.
REASONS = {
    "false_positive": ("False positive", 0.0),
    "compensating_control": ("Compensating control", 0.5),
    "risk_accepted": ("Risk accepted", 1.0),
    "planned_fix": ("Planned fix", 1.0),
}
MAX_EXCEPTION_DAYS = 365

# A failed posture rule has no CVE, so its severity stands in for (tier, CVSS). Through base()
# and sla_days() that gives: critical 83.5 and 14 days, high 62 and 30 days, medium 24 and
# 90 days, low 12 and 90 days. A critical setting outranks every CVE without exploit code.
POSTURE_SEVERITY = {"critical": (2, 9.0), "high": (3, 8.0), "medium": (4, 6.0), "low": (4, 3.0)}


def base(tier: int, cvss: float | None) -> float:
    """Tier sets the band and CVSS places the finding inside it. Bands never overlap."""
    c = UNKNOWN_CVSS if cvss is None else max(0.0, min(10.0, cvss))
    if tier == 1:
        return 90 + c
    if tier == 2:
        return 70 + c * 1.5
    if tier == 3:
        return 50 + c * 1.5
    return c * 4


def importance(dev: Device) -> int:
    return dev.criticality or (4 if dev.is_server else 3)


def sla_days(tier: int, cvss: float | None) -> int:
    """Known exploited or critical: 14 days. High: 30. Everything else: 90."""
    c = cvss or 0.0
    if tier == 1 or c >= 9.0:
        return 14
    if c >= 7.0:
        return 30
    return 90


def is_active(exc: FindingException, today: date) -> bool:
    return exc.revoked_at is None and exc.expires_on >= today


def matches(exc: FindingException, f: Finding) -> bool:
    return (
        (exc.device_id is None or exc.device_id == f.device_id)
        and (exc.fix_key is None or exc.fix_key == f.fix_key)
        and (exc.cve_id is None or exc.cve_id == f.cve_id)
    )


def pick(excs: list[FindingException], f: Finding) -> FindingException | None:
    """When several exceptions match, the one that lowers the score most wins, then the latest."""
    hits = [e for e in excs if matches(e, f)]
    return min(hits, key=lambda e: (REASONS[e.reason][1], -e.expires_on.toordinal(), -e.id)) if hits else None


@dataclass
class Breakdown:
    base: float
    importance: int
    importance_factor: float
    exposure: float
    exception_factor: float

    @property
    def risk(self) -> float:
        return round(self.base * self.importance_factor * self.exposure * self.exception_factor, 1)

    def formula(self) -> str:
        parts = [f"{self.base:.0f} base", f"x {self.importance_factor:g} importance"]
        if self.exposure != 1.0:
            parts.append(f"x {self.exposure:g} internet facing")
        if self.exception_factor != 1.0:
            parts.append(f"x {self.exception_factor:g} exception")
        return " ".join(parts)


def breakdown(f: Finding, dev: Device, exc: FindingException | None) -> Breakdown:
    level = importance(dev)
    return Breakdown(
        base=base(f.exploit_tier, f.cvss),
        importance=level,
        importance_factor=IMPORTANCE[level],
        exposure=EXPOSED if dev.internet_facing else 1.0,
        exception_factor=REASONS[exc.reason][1] if exc else 1.0,
    )


def active_exceptions(s: Session, client_id: int, today: date | None = None) -> list[FindingException]:
    today = today or utcnow().date()
    return list(s.scalars(select(FindingException).where(
        FindingException.client_id == client_id,
        FindingException.revoked_at.is_(None),
        FindingException.expires_on >= today,
    )))


def rescore(s: Session, dev: Device, now: datetime | None = None) -> int:
    """Recompute risk, deadline and exception for every open finding on one device."""
    now = now or utcnow()
    client_id = s.scalar(select(Site.client_id).where(Site.id == dev.site_id))
    excs = [e for e in active_exceptions(s, client_id, now.date()) if e.device_id in (None, dev.id)]
    n = 0
    for f in s.scalars(select(Finding).where(Finding.device_id == dev.id, Finding.status == "open")):
        exc = pick(excs, f)
        f.exception_id = exc.id if exc else None
        f.risk = breakdown(f, dev, exc).risk
        f.due_at = f.opened_at + timedelta(days=sla_days(f.exploit_tier, f.cvss))
        n += 1
    s.flush()
    return n


def rescore_client(s: Session, client_id: int, device_id: int | None = None) -> int:
    q = select(Device).join(Site, Site.id == Device.site_id).where(Site.client_id == client_id)
    if device_id is not None:
        q = q.where(Device.id == device_id)
    return sum(rescore(s, d) for d in s.scalars(q).all())


def rescore_lapsed(s: Session) -> int:
    """Devices with an open finding held by an exception that was revoked or has expired."""
    today = utcnow().date()
    ids = s.scalars(
        select(Finding.device_id).distinct()
        .join(FindingException, FindingException.id == Finding.exception_id)
        .where(Finding.status == "open", or_(FindingException.revoked_at.is_not(None), FindingException.expires_on < today))
    ).all()
    for dev in s.scalars(select(Device).where(Device.id.in_(ids))).all() if ids else []:
        rescore(s, dev)
    return len(ids)


def overdue_clause(now: datetime):
    """SQL condition for an open finding past its deadline with no active exception."""
    return and_(Finding.status == "open", Finding.due_at < now, Finding.exception_id.is_(None))
