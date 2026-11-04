import gzip
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, findings, tenants
from bearwatch.api import app
from bearwatch.models import CpeMatch, Device, Finding, FindingEvent, MsrcFix, MsrcProduct, WingetPackage

WIN11 = "Windows 11 Version 23H2 for x64-based Systems"
GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _seed():
    with db.session_scope() as s:
        s.add(MsrcProduct(product_id="12242", name=WIN11))
        s.add(MsrcFix(doc_id="2026-Sep", cve_id="CVE-2026-0001", product_id="12242", kb="5040001", fixed_build="10.0.22631.4100", supersedes=[]))
        s.add(MsrcFix(doc_id="2026-Oct", cve_id="CVE-2026-0002", product_id="12242", kb="5050001", fixed_build="10.0.22631.4300", supersedes=["5040001"]))
        s.add(WingetPackage(id="Google.Chrome", name="Google Chrome", latest_version="131.0.6778.86", norm_names=[], norm_publishers=[], product_codes=[]))
        base = {"criteria": "x", "part": "a", "vendor": "google", "product": "chrome", "version": "*", "target_sw": "*", "platforms": []}
        s.add(CpeMatch(cve_id="CVE-2023-7024", version_end_excl="120.0.6099.129", **base))
        # A heuristic-only program: must not produce findings.
        s.add(CpeMatch(cve_id="CVE-2024-1111", criteria="x", part="a", vendor="acme", product="widgetpro", version="2.0", target_sw="*", platforms=[]))
        client = tenants.create_client(s, "Bearium Networks")
        _, key = tenants.create_site(s, client, "Orlando office")
    return key


def _inventory(build: str, chrome: str, h: str) -> dict:
    return {
        "hash": h,
        "agent_version": "0.1.0",
        "hostname": "BEAR-PC01",
        "os": {"caption": "Windows 11 Pro 23H2", "build": build, "arch": "x64"},
        "kbs": ["KB5040001"],
        "software": [
            {"name": "Google Chrome", "version": chrome, "publisher": "Google LLC"},
            {"name": "Google Chrome", "version": chrome, "publisher": "Google LLC"},  # dup registry view
            {"name": "WidgetPro 2.0", "version": "2.0", "publisher": "Acme"},
        ],
    }


def _post_inv(c, token, inv):
    body = gzip.compress(json.dumps(inv).encode())
    return c.post("/api/agent/inventory", content=body, headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip", "Content-Type": "application/json"})


def _evaluate():
    with db.session_scope() as s:
        return findings.evaluate(s, s.scalars(select(Device)).one())


def test_agent_lifecycle(session):
    key = _seed()
    with TestClient(app) as c:
        assert c.post("/api/agent/enroll", json={"enroll_key": "bwe_wrong_key_123", "machine_guid": GUID, "hostname": "x", "agent_version": "0.1.0"}).status_code == 401
        r = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID, "hostname": "BEAR-PC01", "agent_version": "0.1.0"})
        assert r.status_code == 200
        token = r.json()["token"]
        assert token.startswith("bwd_") and r.json()["upload"] is True

        auth = {"Authorization": f"Bearer {token}"}
        assert c.post("/api/agent/heartbeat", json={"agent_version": "0.1.0"}, headers={"Authorization": "Bearer bwd_nope"}).status_code == 401
        assert c.post("/api/agent/heartbeat", json={"agent_version": "0.1.0", "inventory_hash": "aaaaaaaa"}, headers=auth).json()["upload"] is True

        # Build .4200: CVE-0001 fixed by build, CVE-0002 open. Chrome 120.0.6099.71 is vulnerable.
        assert _post_inv(c, token, _inventory("10.0.22631.4200", "120.0.6099.71", "aaaaaaaa")).status_code == 202
        hb = c.post("/api/agent/heartbeat", json={"agent_version": "0.1.0", "inventory_hash": "aaaaaaaa"}, headers=auth).json()
        assert hb["upload"] is False and hb["wua_due"] is False  # unchanged PC uploads nothing

        counts = _evaluate()
        assert counts == {"found": 2, "fixed": 0, "reopened": 0, "open": 2}
        with db.session_scope() as s:
            by_cve = {f.cve_id: f for f in s.scalars(select(Finding))}
            assert by_cve["CVE-2026-0002"].fix_key == "kb:5050001" and by_cve["CVE-2026-0002"].source == "os"
            assert by_cve["CVE-2023-7024"].fix_key == "winget:Google.Chrome"
            assert by_cve["CVE-2023-7024"].fix_label == "Update Google Chrome to 131.0.6778.86"
            assert "CVE-2024-1111" not in by_cve  # heuristic match is a suggestion only

        # Patch Windows and Chrome: both findings close, history kept.
        _post_inv(c, token, _inventory("10.0.22631.4317", "131.0.6778.86", "bbbbbbbb"))
        assert _evaluate() == {"found": 0, "fixed": 2, "reopened": 0, "open": 0}

        # Chrome rolled back: the old finding reopens instead of duplicating.
        _post_inv(c, token, _inventory("10.0.22631.4317", "120.0.6099.71", "cccccccc"))
        assert _evaluate()["reopened"] == 1

        # Reinstall: re-enrolling the same machine keeps the device and its findings.
        r2 = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID.upper(), "hostname": "BEAR-PC01", "agent_version": "0.1.1"})
        assert r2.json()["device_id"] == r.json()["device_id"]
        assert c.post("/api/agent/heartbeat", json={"agent_version": "0.1.1"}, headers=auth).status_code == 401  # old token revoked

    with db.session_scope() as s:
        events = [e.event for e in s.scalars(select(FindingEvent).order_by(FindingEvent.id))]
        assert events == ["found", "found", "fixed", "fixed", "reopened"]


def test_inventory_rejects_bombs_and_junk(session):
    key = _seed()
    with TestClient(app) as c:
        token = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID, "hostname": "h", "agent_version": "0.1.0"}).json()["token"]
        h = {"Authorization": f"Bearer {token}", "Content-Encoding": "gzip"}
        assert c.post("/api/agent/inventory", content=b"not gzip", headers=h).status_code == 400
        bomb = gzip.compress(b"{" + b" " * (20 * 1024 * 1024))
        assert c.post("/api/agent/inventory", content=bomb, headers=h).status_code == 413
        bad = gzip.compress(json.dumps({"hash": "x"}).encode())
        assert c.post("/api/agent/inventory", content=bad, headers=h).status_code == 422
