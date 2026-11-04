"""Known Exploited Vulnerabilities: CISA's catalog (always) and VulnCheck KEV (when a token is set).

CISA KEV is the US government list (public domain). VulnCheck KEV is broader and free with a
community account; check VulnCheck's current terms before redistributing its data.
"""

import httpx
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import upsert
from ..models import Kev
from .common import get_with_retry, log, make_client, parse_date

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNCHECK_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"


def parse_cisa(doc: dict) -> list[dict]:
    rows = []
    for v in doc.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        rows.append(
            {
                "cve_id": cve,
                "source": "cisa",
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": (v.get("vulnerabilityName") or "")[:400] or None,
                "date_added": parse_date(v.get("dateAdded")),
                "due_date": parse_date(v.get("dueDate")),
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            }
        )
    return rows


def parse_vulncheck(items: list[dict]) -> list[dict]:
    rows = []
    for v in items:
        for cve in v.get("cve") or []:
            cve = cve.strip().upper()
            if not cve.startswith("CVE-"):
                continue
            rows.append(
                {
                    "cve_id": cve,
                    "source": "vulncheck",
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "name": (v.get("vulnerabilityName") or "")[:400] or None,
                    "date_added": parse_date(v.get("date_added")),
                    "due_date": parse_date(v.get("dueDate")),
                    "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                }
            )
    return rows


def sync_cisa(session: Session, client: httpx.Client | None = None) -> int:
    client = client or make_client()
    rows = parse_cisa(get_with_retry(client, CISA_URL).json())
    # Dedupe on key; the catalog should not repeat a CVE but never trust that.
    rows = list({r["cve_id"]: r for r in rows}.values())
    return upsert(session, Kev, rows, key=("cve_id", "source"))


def sync_vulncheck(session: Session, client: httpx.Client | None = None) -> int:
    """Page through VulnCheck's KEV index. Skipped (returns 0) without a token.

    Not yet exercised against the live API in this repo: confirm pagination fields on first use.
    """
    token = get_settings().vulncheck_api_token
    if not token:
        log.info("VulnCheck token not set, skipping VulnCheck KEV")
        return 0
    client = client or make_client()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    page, total_pages, rows = 1, 1, []
    while page <= total_pages:
        r = get_with_retry(client, VULNCHECK_URL, params={"page": page, "limit": 500}, headers=headers)
        body = r.json()
        rows.extend(parse_vulncheck(body.get("data") or []))
        total_pages = int((body.get("_meta") or {}).get("total_pages") or page)
        page += 1
    rows = list({r["cve_id"]: r for r in rows}.values())
    return upsert(session, Kev, rows, key=("cve_id", "source"))
