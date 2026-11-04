import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import auth, config, db, findings
from bearwatch.api import app
from bearwatch.models import Device, Site

from .test_agent import GUID, _inventory, _post_inv, _seed

ORIGIN = {"Origin": "http://testserver"}


def _sign_in(c: TestClient) -> None:
    r = c.post("/login", data={"token": "test-token"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_token_sign_in_and_pages(session):
    key = _seed()
    with TestClient(app) as c:
        assert c.get("/", follow_redirects=False).headers["location"] == "/login"
        assert c.post("/login", data={"token": "wrong"}, headers=ORIGIN, follow_redirects=False).headers["location"] == "/login?error=1"
        _sign_in(c)

        r = c.get("/")
        assert r.status_code == 200 and "Overview" in r.text
        assert "script-src 'none'" in r.headers["content-security-policy"]

        # Enroll a device and give it findings, then render every page.
        token = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID, "hostname": "BEAR-PC01", "agent_version": "0.1.0"}).json()["token"]
        _post_inv(c, token, _inventory("10.0.22631.4200", "120.0.6099.71", "aaaaaaaa"))
        with db.session_scope() as s:
            findings.evaluate_pending(s)
            dev_id = s.scalars(select(Device)).one().id

        home = c.get("/").text
        assert "Install KB5050001" in home and "Update Google Chrome to 131.0.6778.86" in home
        assert "Bearium Networks" in c.get("/clients/1").text
        fix = c.get("/fix", params={"key": "winget:Google.Chrome", "client": 1}).text
        assert "BEAR-PC01" in fix and "CVE-2023-7024" in fix and "winget upgrade --id Google.Chrome -e" in fix
        page = c.get(f"/devices/{dev_id}").text
        assert "BEAR-PC01" in page and "CVE-2026-0002" in page and "Not run on this device" in page
        assert "WidgetPro" in c.get("/software").text  # heuristic-only program listed for mapping
        assert c.get("/devices/999").status_code == 404

        # Rescan request reaches the agent on its next heartbeat.
        assert c.post(f"/devices/{dev_id}/rescan", headers=ORIGIN, follow_redirects=False).status_code == 303
        hb = c.post("/api/agent/heartbeat", json={"agent_version": "0.1.0", "inventory_hash": "aaaaaaaa"}, headers={"Authorization": f"Bearer {token}"}).json()
        assert hb["collect_now"] is True and hb["upload"] is True


def test_admin_forms_and_csrf(session):
    with TestClient(app) as c:
        _sign_in(c)
        # Cross-site and origin-less posts are refused.
        assert c.post("/admin/clients", data={"name": "Evil"}, headers={"Origin": "https://evil.example"}).status_code == 403
        assert c.post("/admin/clients", data={"name": "Evil"}).status_code == 403

        assert c.post("/admin/clients", data={"name": "Acme Plumbing"}, headers=ORIGIN, follow_redirects=False).status_code == 303
        dup = c.post("/admin/clients", data={"name": "Acme Plumbing"}, headers=ORIGIN, follow_redirects=False)
        assert "already%20exists" in dup.headers["location"]

        r = c.post("/admin/sites", data={"client_id": 1, "name": "Main office", "wua_check": "true"}, headers=ORIGIN)
        assert r.status_code == 200 and "bwe_" in r.text and "bw-agent.exe enroll --server http://testserver --key bwe_" in r.text
        with db.session_scope() as s:
            site = s.scalars(select(Site)).one()
            assert site.wua_check is True and "bwe_" not in site.enroll_key_hash  # only the hash is stored

        assert "New enrollment key" in c.post(f"/admin/sites/{site.id}/rotate", headers=ORIGIN).text
        c.post(f"/admin/sites/{site.id}/wua", headers=ORIGIN)
        with db.session_scope() as s:
            assert s.get(Site, site.id).wua_check is False


@pytest.fixture()
def cloudflare(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class FakeJwks:
        def get_signing_key_from_jwt(self, _token):
            return type("K", (), {"key": key.public_key()})()

    monkeypatch.setenv("BEARWATCH_DASHBOARD_AUTH", "cloudflare")
    monkeypatch.setenv("BEARWATCH_CF_ACCESS_TEAM_DOMAIN", "bearium.cloudflareaccess.com")
    monkeypatch.setenv("BEARWATCH_CF_ACCESS_AUD", "aud-tag-123")
    config.get_settings.cache_clear()
    monkeypatch.setattr(auth, "_jwks", lambda _team: FakeJwks())

    def make(aud="aud-tag-123", iss="https://bearium.cloudflareaccess.com", exp=3600, signer=key):
        claims = {"aud": [aud], "iss": iss, "email": "tech@bearium.net", "exp": int(time.time()) + exp}
        return jwt.encode(claims, signer, algorithm="RS256")

    yield make
    config.get_settings.cache_clear()


def test_cloudflare_access(session, cloudflare):
    with TestClient(app) as c:
        assert c.get("/").status_code == 403  # no Access token: refused, not redirected to a token form
        ok = c.get("/", headers={"Cf-Access-Jwt-Assertion": cloudflare()})
        assert ok.status_code == 200 and "tech@bearium.net" in ok.text
        assert c.get("/", cookies={"CF_Authorization": cloudflare()}).status_code == 200
        assert c.get("/", headers={"Cf-Access-Jwt-Assertion": cloudflare(aud="other-app")}).status_code == 403
        assert c.get("/", headers={"Cf-Access-Jwt-Assertion": cloudflare(iss="https://evil.cloudflareaccess.com")}).status_code == 403
        assert c.get("/", headers={"Cf-Access-Jwt-Assertion": cloudflare(exp=-60)}).status_code == 403
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert c.get("/", headers={"Cf-Access-Jwt-Assertion": cloudflare(signer=other)}).status_code == 403
        # The token sign-in form is disabled in this mode.
        assert c.post("/login", data={"token": "test-token"}, headers=ORIGIN, follow_redirects=False).headers["location"] == "/login?error=1"
        # Agents never go through Access.
        assert c.post("/api/agent/heartbeat", json={"agent_version": "0.1.0"}).status_code == 401
