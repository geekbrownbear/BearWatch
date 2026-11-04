"""Microsoft Security Response Center CVRF API v3.

This is the source of truth for Windows: which KB fixes which CVE on which exact product,
the fixed build number, and which older KB each update supersedes. Windows CVEs are matched
from here, never from NVD CPE data.

Only months whose CurrentReleaseDate changed since the last run are downloaded again.
"""

import json
import re
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import upsert
from ..models import MsrcDocument, MsrcFix, MsrcProduct, MsrcVuln
from .common import get_with_retry, log, make_client, parse_dt, utcnow

BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
_KB = re.compile(r"^\s*(?:KB)?(\d{6,8})\s*$", re.I)

# CVRF remediation and threat type codes.
VENDOR_FIX = 2
THREAT_IMPACT, THREAT_EXPLOIT_STATUS, THREAT_SEVERITY = 0, 1, 3


def _kb(value: str | None) -> str | None:
    if not value:
        return None
    m = _KB.match(value)
    return m.group(1) if m else value.strip()[:64]


def _supersedes(value: str | None) -> list[str]:
    if not value:
        return []
    out = []
    for part in re.split(r"[,;\s]+", value):
        m = _KB.match(part)
        if m:
            out.append(m.group(1))
    return out


def _per_product(entries: list[dict], type_code: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for t in entries or []:
        if t.get("Type") != type_code:
            continue
        val = (t.get("Description") or {}).get("Value")
        for pid in t.get("ProductID") or []:
            out[pid] = val
    return out


def parse_document(doc_id: str, doc: dict) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (products, vulns, fixes) rows for one monthly document."""
    products = [
        {"product_id": p["ProductID"], "name": p.get("Value", "")[:400], "cpe": (p.get("CPE") or None)}
        for p in (doc.get("ProductTree") or {}).get("FullProductName", [])
        if p.get("ProductID")
    ]
    vulns, fixes = [], []
    for v in doc.get("Vulnerability") or []:
        cve = (v.get("CVE") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        threats = v.get("Threats") or []
        # Exploit status entries usually carry no ProductID, so read them directly.
        status = " ".join(
            (t.get("Description") or {}).get("Value") or "" for t in threats if t.get("Type") == THREAT_EXPLOIT_STATUS
        ).lower()
        # Exploit status is written like "Publicly Disclosed:No;Exploited:Yes;..."
        vulns.append(
            {
                "cve_id": cve,
                "doc_id": doc_id,
                "title": ((v.get("Title") or {}).get("Value") or "")[:400] or None,
                "exploited": "exploited:yes" in status,
                "publicly_disclosed": "publicly disclosed:yes" in status,
            }
        )
        severity = _per_product(threats, THREAT_SEVERITY)
        impact = _per_product(threats, THREAT_IMPACT)
        cvss: dict[str, float] = {}
        for s in v.get("CVSSScoreSets") or []:
            for pid in s.get("ProductID") or []:
                cvss[pid] = s.get("BaseScore")
        for r in v.get("Remediations") or []:
            if r.get("Type") != VENDOR_FIX:
                continue
            kb = _kb((r.get("Description") or {}).get("Value"))
            # MSRC spells the field "Supercedence".
            sup = _supersedes(r.get("Supercedence") or r.get("Supersedence"))
            for pid in r.get("ProductID") or []:
                fixes.append(
                    {
                        "doc_id": doc_id,
                        "cve_id": cve,
                        "product_id": pid,
                        "kb": kb,
                        "fixed_build": (r.get("FixedBuild") or None),
                        "supersedes": sup,
                        "subtype": r.get("SubType"),
                        "url": (r.get("URL") or "")[:400] or None,
                        "severity": severity.get(pid),
                        "impact": (impact.get(pid) or "")[:64] or None,
                        "cvss_score": cvss.get(pid),
                    }
                )
    return products, vulns, fixes


def store_document(session: Session, doc_id: str, doc: dict) -> int:
    products, vulns, fixes = parse_document(doc_id, doc)
    upsert(session, MsrcProduct, list({p["product_id"]: p for p in products}.values()), key=("product_id",))
    upsert(session, MsrcVuln, list({v["cve_id"]: v for v in vulns}.values()), key=("cve_id",))
    session.execute(delete(MsrcFix).where(MsrcFix.doc_id == doc_id))
    if fixes:
        session.execute(MsrcFix.__table__.insert(), fixes)
    return len(fixes)


def sync(session: Session, client: httpx.Client | None = None, months: int | None = None) -> int:
    client = client or make_client(timeout=300)
    months = months or get_settings().msrc_months
    cutoff = utcnow() - timedelta(days=31 * months)
    index = get_with_retry(client, f"{BASE}/updates", headers={"Accept": "application/json"}).json()["value"]
    known = {d.id: d.current_release for d in session.scalars(select(MsrcDocument))}
    written = 0
    for entry in sorted(index, key=lambda e: e.get("InitialReleaseDate") or ""):
        initial = parse_dt(entry.get("InitialReleaseDate"))
        current = parse_dt(entry.get("CurrentReleaseDate"))
        if initial is None or initial < cutoff:
            continue
        doc_id = entry["ID"]
        if doc_id in known and known[doc_id] == current:
            continue
        log.info("msrc: fetching %s", doc_id)
        r = get_with_retry(client, entry["CvrfUrl"], headers={"Accept": "application/json"})
        doc = json.loads(r.content.decode("utf-8"))
        written += store_document(session, doc_id, doc)
        session.merge(
            MsrcDocument(
                id=doc_id,
                title=entry.get("DocumentTitle"),
                initial_release=initial,
                current_release=current,
                synced_at=utcnow(),
            )
        )
        session.commit()
    return written
