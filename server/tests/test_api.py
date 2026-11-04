from fastapi.testclient import TestClient

from bearwatch.api import app


def test_health_and_auth(session):
    with TestClient(app) as c:
        assert c.get("/api/health").json()["status"] == "ok"
        assert c.get("/api/intel/status").status_code == 401
        assert c.get("/api/intel/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
        r = c.get("/api/intel/status", headers={"Authorization": "Bearer test-token"})
        assert r.status_code == 200 and r.json() == []


def test_match_endpoints(session):
    h = {"Authorization": "Bearer test-token"}
    with TestClient(app) as c:
        assert c.post("/api/match/windows", json={"build": "bad"}, headers=h).status_code == 422
        # No MSRC data loaded yet: product lookup fails cleanly.
        assert c.post("/api/match/windows", json={"build": "10.0.22631.4317"}, headers=h).status_code == 404
        r = c.post("/api/match/app", json={"name": "Google Chrome", "version": "120.0"}, headers=h)
        assert r.status_code == 200 and r.json()["resolved_by"] == "override"
