"""WinGet community repository index.

Gives us, per package: the latest version (to say "update to X") and the normalized names,
publishers and MSI product codes that let us link a program from the Windows Uninstall
registry to a package id (and later to a `winget upgrade --id` fix).
"""

import sqlite3
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from ..db import upsert
from ..models import WingetPackage
from ..versions import Version
from .common import get_with_retry, make_client

URL = "https://cdn.winget.microsoft.com/cache/source.msix"


def parse_index(db_path: Path) -> list[dict]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        q = """
            SELECT m.rowid, i.id, n.name, v.version
            FROM manifest m
            JOIN ids i ON i.rowid = m.id
            JOIN names n ON n.rowid = m.name
            JOIN versions v ON v.rowid = m.version
        """
        latest: dict[str, tuple[Version, str, str, int]] = {}
        for rowid, pid, name, ver in con.execute(q):
            cur = latest.get(pid)
            vv = Version(ver)
            if cur is None or vv > cur[0]:
                latest[pid] = (vv, ver, name, rowid)

        def mapped(table: str, col: str) -> dict[int, list[str]]:
            out: dict[int, list[str]] = defaultdict(list)
            sql = f"SELECT mp.manifest, t.{col} FROM {table}_map mp JOIN {table} t ON t.rowid = mp.{col}"
            for manifest, val in con.execute(sql):
                out[manifest].append(val)
            return out

        names = mapped("norm_names", "norm_name")
        pubs = mapped("norm_publishers", "norm_publisher")
        codes = mapped("productcodes", "productcode")
    finally:
        con.close()

    rows = []
    for pid, (_, ver, name, rowid) in latest.items():
        rows.append(
            {
                "id": pid[:200],
                "name": name[:400],
                "latest_version": ver[:120],
                "norm_names": sorted(set(names.get(rowid, []))),
                "norm_publishers": sorted(set(pubs.get(rowid, []))),
                "product_codes": sorted({c.upper() for c in codes.get(rowid, [])}),
            }
        )
    return rows


def sync(session: Session, client: httpx.Client | None = None) -> int:
    client = client or make_client(timeout=300)
    raw = get_with_retry(client, URL).content
    with tempfile.TemporaryDirectory() as tmp:
        msix = Path(tmp) / "source.msix"
        msix.write_bytes(raw)
        with zipfile.ZipFile(msix) as z:
            z.extract("Public/index.db", tmp)
        rows = parse_index(Path(tmp) / "Public" / "index.db")
    return upsert(session, WingetPackage, rows, key=("id",))
