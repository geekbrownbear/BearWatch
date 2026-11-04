"""NVD CVE API 2.0 sync.

This product uses the NVD API but is not endorsed or certified by the NVD.

First run pages through every CVE (about 160 requests). Later runs ask only for CVEs modified
since the last successful run, in windows of at most 120 days as the API requires.
"""

import time
from datetime import timedelta

import httpx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import upsert
from ..models import CpeMatch, Cve, SyncState
from .common import get_with_retry, log, make_client, parse_date, parse_dt, utcnow

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
MAX_WINDOW = timedelta(days=119)

# Preference order when a CVE carries several CVSS metrics.
_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _pick_cvss(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    for key in _METRICS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Primary (NVD's own) score first, then any secondary (CNA) score.
        entries = sorted(entries, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        m = entries[0]
        data = m.get("cvssData", {})
        severity = data.get("baseSeverity") or m.get("baseSeverity")
        return data.get("version"), data.get("baseScore"), data.get("vectorString"), severity
    return None, None, None, None


def _split_cpe(criteria: str) -> dict | None:
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    p = criteria.split(":")
    if len(p) < 13:
        return None
    return {"part": p[2], "vendor": p[3], "product": p[4], "version": p[5], "target_sw": p[10]}


def parse_item(item: dict) -> tuple[dict, list[dict]]:
    c = item["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), None)
    ver, score, vector, sev = _pick_cvss(c.get("metrics") or {})
    row = {
        "id": c["id"],
        "published": parse_dt(c.get("published")),
        "last_modified": parse_dt(c.get("lastModified")),
        "status": c.get("vulnStatus"),
        "description": desc,
        "cvss_version": ver,
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": (sev or "").upper() or None,
        "nvd_kev_added": parse_date(c.get("cisaExploitAdd")),
    }
    matches: list[dict] = []
    seen: set[tuple] = set()
    for conf in c.get("configurations") or []:
        nodes = conf.get("nodes") or []
        # In an AND configuration the non-vulnerable entries are the platform the software must
        # be running on (Chrome AND macOS). Record them so other platforms don't match.
        platforms: list[str] = []
        if (conf.get("operator") or "").upper() == "AND":
            for node in nodes:
                for m in node.get("cpeMatch") or []:
                    if not m.get("vulnerable"):
                        p = _split_cpe(m.get("criteria", ""))
                        if p:
                            platforms.append(f"{p['vendor']}:{p['product']}")
        platforms = sorted(set(platforms))
        for node in nodes:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                parts = _split_cpe(m.get("criteria", ""))
                if not parts:
                    continue
                rec = {
                    "cve_id": c["id"],
                    "criteria": m["criteria"][:400],
                    **parts,
                    "version_start_incl": m.get("versionStartIncluding"),
                    "version_start_excl": m.get("versionStartExcluding"),
                    "version_end_incl": m.get("versionEndIncluding"),
                    "version_end_excl": m.get("versionEndExcluding"),
                    "platforms": platforms,
                }
                k = tuple(str(v) for v in rec.values())
                if k not in seen:
                    seen.add(k)
                    matches.append(rec)
    return row, matches


def store_page(session: Session, items: list[dict]) -> int:
    cves, matches = [], []
    for it in items:
        row, m = parse_item(it)
        cves.append(row)
        matches.extend(m)
    if not cves:
        return 0
    ids = [r["id"] for r in cves]
    upsert(session, Cve, cves, key=("id",))
    # Configurations are replaced wholesale whenever NVD modifies a CVE.
    session.execute(delete(CpeMatch).where(CpeMatch.cve_id.in_(ids)))
    if matches:
        session.execute(CpeMatch.__table__.insert(), matches)
    return len(cves)


def _fetch(client: httpx.Client, params: dict, pause: float) -> dict:
    headers = {}
    key = get_settings().nvd_api_key
    if key:
        headers["apiKey"] = key
    body = get_with_retry(client, URL, params=params, headers=headers, backoff=10.0).json()
    time.sleep(pause)
    return body


def _page_through(session: Session, client: httpx.Client, base: dict, pause: float) -> int:
    start, total, written = 0, None, 0
    while total is None or start < total:
        body = _fetch(client, {**base, "startIndex": start, "resultsPerPage": PAGE}, pause)
        total = body.get("totalResults", 0)
        items = body.get("vulnerabilities", [])
        written += store_page(session, items)
        session.commit()  # keep progress if a long first sync is interrupted
        log.info("nvd: %d/%d", min(start + PAGE, total), total)
        if not items:
            break
        start += len(items)
    return written


def sync(session: Session, client: httpx.Client | None = None) -> int:
    client = client or make_client(timeout=180)
    # Public rate limit: 5 requests / 30 s without a key, 50 with one.
    pause = 0.8 if get_settings().nvd_api_key else 6.5
    state = session.get(SyncState, "nvd")
    since = parse_dt(state.cursor) if state and state.cursor else None
    run_started = utcnow()

    if since is None:
        written = _page_through(session, client, {}, pause)
    else:
        written = 0
        window_start = since - timedelta(minutes=5)
        while window_start < run_started:
            window_end = min(window_start + MAX_WINDOW, run_started)
            params = {
                "lastModStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            }
            written += _page_through(session, client, params, pause)
            window_start = window_end

    state = session.get(SyncState, "nvd") or SyncState(source="nvd")
    state.cursor = run_started.isoformat()
    session.merge(state)
    return written
