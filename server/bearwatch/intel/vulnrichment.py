"""CISA vulnrichment (ADP) SSVC decision points, fetched on demand.

The full repository is ~400 MB, so instead of mirroring it we fetch the one JSON file for a CVE
when that CVE first shows up in a finding, and cache the answer (including "not enriched").
"""

import re
from datetime import timedelta

import httpx
from sqlalchemy.orm import Session

from ..models import Ssvc
from .common import make_client, utcnow

RAW = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
REFRESH_AFTER = timedelta(days=14)


def path_for(cve_id: str) -> str:
    m = _CVE.match(cve_id.upper())
    if not m:
        raise ValueError(f"not a CVE id: {cve_id}")
    year, num = m.group(1), m.group(2)
    bucket = f"{int(num) // 1000}xxx"
    return f"{RAW}/{year}/{bucket}/{cve_id.upper()}.json"


def parse(doc: dict) -> dict:
    for adp in (doc.get("containers") or {}).get("adp") or []:
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        for metric in adp.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            opts: dict[str, str] = {}
            for o in (other.get("content") or {}).get("options") or []:
                opts.update({k.lower(): str(v).lower() for k, v in o.items()})
            return {
                "found": True,
                "exploitation": opts.get("exploitation"),
                "automatable": opts.get("automatable"),
                "technical_impact": opts.get("technical impact"),
            }
    return {"found": False, "exploitation": None, "automatable": None, "technical_impact": None}


def enrich(session: Session, cve_ids: list[str], client: httpx.Client | None = None, limit: int = 50) -> int:
    """Fetch SSVC for CVEs not cached (or stale). Caps network calls per invocation."""
    client = client or make_client(timeout=30)
    now, fetched = utcnow(), 0
    for cve in dict.fromkeys(c.upper() for c in cve_ids):
        if fetched >= limit:
            break
        cached = session.get(Ssvc, cve)
        if cached and now - cached.fetched_at < REFRESH_AFTER:
            continue
        r = client.get(path_for(cve))
        if r.status_code == 404:
            data = parse({})
        else:
            r.raise_for_status()
            data = parse(r.json())
        session.merge(Ssvc(cve_id=cve, fetched_at=now, **data))
        fetched += 1
    return fetched
