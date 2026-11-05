"""Turn a device's stored inventory into findings, and keep their history.

Each evaluation computes the device's current set of (source, subject, CVE) and reconciles it
with the stored findings: new ones are "found", ones that disappeared are "fixed", and fixed
ones that come back are "reopened". Nothing is deleted, so reports can show progress.

Failed posture rules (posture.py) are findings too, with source "posture" and the rule id in
place of a CVE.

Only programs resolved through intel/cpe_overrides.json produce findings. A heuristic match is
kept on the software row as a suggestion for the overrides file, never counted, because a
wrong vendor guess would put false CVEs in front of a client.
"""

import logging
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .intel.common import utcnow
from . import posture, scoring
from .match import apps, windows
from .match.enrich import CveContext
from .models import Device, DeviceKb, DeviceSoftware, Finding, FindingEvent, WingetPackage

log = logging.getLogger("bearwatch.findings")
WINDOWS = "windows"


@dataclass
class Current:
    subject: str
    subject_version: str | None
    fix_key: str
    fix_label: str
    ctx: CveContext


def _os_findings(s: Session, dev: Device) -> dict[tuple[str, str, str], Current]:
    kbs = list(s.scalars(select(DeviceKb.kb).where(DeviceKb.device_id == dev.id)))
    r = windows.match(s, dev.os_product, dev.os_build, kbs)
    # Each open CVE is credited to the first update (most closed first) that would close it,
    # which is normally the latest cumulative update.
    fix_for: dict[str, dict] = {}
    for g in r.by_fix:
        for cve in g["closed"]:
            fix_for.setdefault(cve, g)
    out = {}
    pending = set(dev.pending_kbs or [])
    for o in r.open:
        g = fix_for.get(o.cve_id)
        kb = g["kb"] if g else (o.fixes[0]["kb"] if o.fixes else "unknown")
        if not kb.isdigit():
            label = f"Install the update for {o.cve_id}"
        elif kb in pending:
            # This exact update is installed; only the restart is missing. Other open fixes on
            # the same device still need installing, so they keep the plain label.
            label = f"Install KB{kb} (a restart is pending)"
        else:
            label = f"Install KB{kb}"
        out[("os", WINDOWS, o.cve_id)] = Current(dev.os_caption or r.product, dev.os_build, f"kb:{kb}", label, o.context)
    return out


def _app_findings(s: Session, dev: Device) -> dict[tuple[str, str, str], Current]:
    out: dict[tuple[str, str, str], Current] = {}
    pkg_names: dict[str, str] = {}
    for sw in s.scalars(select(DeviceSoftware).where(DeviceSoftware.device_id == dev.id)):
        if not sw.version:
            continue
        res = apps.match(s, sw.name, sw.version, sw.publisher)
        sw.resolved_by, sw.cpe = res.resolved_by, [list(p) for p in res.cpe]
        sw.winget_id, sw.latest_version = res.winget_id, res.latest_version
        if res.resolved_by != "override" or not res.cves:
            continue
        subject_key = (apps.normalize(sw.name) or sw.name.lower())[:200]
        if res.winget_id:
            if res.winget_id not in pkg_names:
                pkg = s.get(WingetPackage, res.winget_id)
                pkg_names[res.winget_id] = pkg.name if pkg else sw.name
            to = f" to {res.latest_version}" if res.latest_version else ""
            fix_key, label = f"winget:{res.winget_id}", f"Update {pkg_names[res.winget_id]}{to}"
        else:
            fix_key, label = f"app:{subject_key}", f"Update {sw.name}"
        for c in res.cves:
            k = ("app", subject_key, c.cve_id)
            if k in out:  # same program installed twice (machine and user, or two versions)
                versions = set(out[k].subject_version.split(", ")) | {sw.version}
                out[k].subject_version = ", ".join(sorted(versions))[:200]
            else:
                out[k] = Current(sw.name, sw.version, fix_key[:220], label[:400], c)
    return out


def _posture_findings(dev: Device) -> tuple[dict[tuple[str, str, str], Current], set[str] | None]:
    """(failed rules as findings, rule ids that could not be judged). None for the second means
    the device never reported posture (agent before 0.2.0), so nothing can be judged."""
    if not dev.posture:
        return {}, None
    out, unknown = {}, set()
    for r in posture.evaluate(posture.ruleset(), dev.posture.get("values") or {}, dev.is_server, posture.build_number(dev.os_build)):
        if r.status == "unknown":
            unknown.add(r.rule.id)
        elif r.status == "fail":
            tier, score = scoring.POSTURE_SEVERITY[r.rule.severity]
            ctx = CveContext(cve_id=r.rule.id, cvss=score, exploit_tier=tier)
            out[("posture", r.rule.id, r.rule.id)] = Current(r.rule.title, None, r.rule.fix_key, r.rule.fix, ctx)
    return out, unknown


def evaluate(s: Session, dev: Device) -> dict[str, int]:
    """Recompute one device's findings. Returns counts of found/fixed/reopened/open."""
    now = utcnow()
    # Claim the request first, before reading any intel. Feed syncs run on another thread; one
    # that finishes while this runs sets needs_match again (on Postgres its UPDATE waits for this
    # row's lock, then lands after we commit), so the device is evaluated again with the new
    # intel. Clearing the flag at the end instead would erase that request.
    s.execute(update(Device).where(Device.id == dev.id).values(needs_match=False))
    current: dict[tuple[str, str, str], Current] = {}
    errors = []
    os_checked = False
    if dev.os_product and dev.os_build:
        try:
            current.update(_os_findings(s, dev))
            os_checked = True
        except LookupError as e:  # MSRC data not loaded yet for this product
            errors.append(str(e))
    elif dev.os_build:
        errors.append(f"unknown Windows build {dev.os_build}; OS findings skipped")
    current.update(_app_findings(s, dev))
    found, unjudged = _posture_findings(dev)
    current.update(found)

    existing = {(f.source, f.subject_key, f.cve_id): f for f in s.scalars(select(Finding).where(Finding.device_id == dev.id))}
    counts = {"found": 0, "fixed": 0, "reopened": 0}
    events = []
    for k, c in current.items():
        f = existing.get(k)
        if f is None:
            f = Finding(device_id=dev.id, source=k[0], subject_key=k[1], cve_id=k[2], first_seen=now, opened_at=now, status="open")
            s.add(f)
            events.append((f, "found"))
            counts["found"] += 1
        elif f.status == "fixed":
            f.status, f.fixed_at, f.opened_at = "open", None, now  # the fix deadline starts again
            events.append((f, "reopened"))
            counts["reopened"] += 1
        f.subject, f.subject_version, f.fix_key, f.fix_label, f.last_seen = c.subject[:400], c.subject_version, c.fix_key, c.fix_label, now
        f.exploit_tier, f.kev, f.epss, f.cvss = c.ctx.exploit_tier, bool(c.ctx.kev), c.ctx.epss, c.ctx.cvss
    kept = 0
    for k, f in existing.items():
        if k not in current and f.status == "open":
            # No data to judge by: absence is not evidence of a fix, so leave these open as they
            # were. For OS findings that is an unknown build or an MSRC gap; for posture, an
            # agent that has not read the values this rule needs yet.
            if (k[0] == "os" and not os_checked) or (k[0] == "posture" and (unjudged is None or k[1] in unjudged)):
                kept += 1
                continue
            f.status, f.fixed_at = "fixed", now
            events.append((f, "fixed"))
            counts["fixed"] += 1
    s.flush()
    s.add_all(FindingEvent(finding_id=f.id, device_id=dev.id, event=e, at=now) for f, e in events)

    dev.last_match_at = now  # needs_match was cleared at the start; see above
    dev.match_error = "; ".join(errors) or None
    counts["open"] = len(current) + kept
    s.flush()
    scoring.rescore(s, dev, now)
    return counts


def mark_all_for_rematch(s: Session) -> int:
    """New intel can open or close findings without any agent change."""
    return s.execute(update(Device).where(Device.last_inventory_at.is_not(None)).values(needs_match=True)).rowcount or 0


def evaluate_pending(s: Session, limit: int = 25) -> int:
    devs = s.scalars(select(Device).where(Device.needs_match.is_(True)).limit(limit)).all()
    for dev in devs:
        try:
            with s.begin_nested():  # a failure rolls back this device only
                c = evaluate(s, dev)
            log.info("device %s (%s): %s", dev.id, dev.hostname, c)
        except Exception as e:  # never let one device stall the queue
            log.exception("device %s evaluation failed", dev.id)
            dev.needs_match, dev.match_error = False, f"evaluation failed: {e}"[:1000]
    return len(devs)
