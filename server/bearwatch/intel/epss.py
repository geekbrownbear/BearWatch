"""FIRST EPSS daily scores. Attribution: EPSS is produced by FIRST (first.org/epss)."""

import csv
import gzip
import io
import re

import httpx
from sqlalchemy.orm import Session

from ..db import upsert
from ..models import Epss
from .common import get_with_retry, make_client, parse_date

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


def parse(raw_gz: bytes) -> list[dict]:
    text = gzip.decompress(raw_gz).decode("utf-8")
    lines = text.splitlines()
    score_date = None
    if lines and lines[0].startswith("#"):
        m = _SCORE_DATE.search(lines[0])
        score_date = parse_date(m.group(1)) if m else None
        lines = lines[1:]
    rows = []
    for rec in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = (rec.get("cve") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        rows.append(
            {
                "cve_id": cve,
                "score": float(rec["epss"]),
                "percentile": float(rec["percentile"]),
                "score_date": score_date,
            }
        )
    return rows


def sync(session: Session, client: httpx.Client | None = None) -> int:
    client = client or make_client()
    return upsert(session, Epss, parse(get_with_retry(client, URL).content), key=("cve_id",))
