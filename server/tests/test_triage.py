from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, findings, scoring, tenants
from bearwatch.api import app
from bearwatch.intel.common import utcnow
from bearwatch.models import Cve, Device, Finding, FindingException, Kev
from bearwatch.web import device_rows, fix_rows

from .test_agent import GUID, _inventory, _post_inv, _seed
from .test_web import ORIGIN, _sign_in

CHROME_CVE = "CVE-2023-7024"


def test_base_bands_and_deadlines():
    assert scoring.base(1, 9.8) == pytest.approx(99.8)
    assert scoring.base(2, 10) == 85 and scoring.base(3, 10) == 65 and scoring.base(4, 10) == 40
    assert scoring.base(4, None) == 20  # unknown CVSS scored as a medium
    # Bands never overlap: the worst tier 3 is below the mildest tier 2, and so on.
    assert scoring.base(3, 10) < scoring.base(2, 0) < scoring.base(1, 0)
    assert scoring.sla_days(1, 4.0) == 14 and scoring.sla_days(4, 9.1) == 14
    assert scoring.sla_days(3, 7.5) == 30 and scoring.sla_days(4, None) == 90


def _client(c):
    key = _seed()
    with db.session_scope() as s:
        s.add(Cve(id=CHROME_CVE, cvss_score=8.8))
        s.add(Kev(cve_id=CHROME_CVE, source="cisa"))
    token = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID, "hostname": "BEAR-PC01", "agent_version": "0.1.1"}).json()["token"]
    _post_inv(c, token, _inventory("10.0.22631.4200", "120.0.6099.71", "aaaaaaaa"))
    with db.session_scope() as s:
        findings.evaluate_pending(s)
        return token, s.scalars(select(Device)).one().id


def _chrome(s) -> Finding:
    return s.scalars(select(Finding).where(Finding.cve_id == CHROME_CVE)).one()


def test_risk_settings_exceptions_and_deadlines(session):
    with TestClient(app) as c:
        _sign_in(c)
        token, dev_id = _client(c)

        with db.session_scope() as s:
            f = _chrome(s)
            assert f.exploit_tier == 1 and f.risk == pytest.approx(98.8)  # 90 + 8.8, normal workstation
            assert f.due_at == f.opened_at + timedelta(days=14)
            kb = s.scalars(select(Finding).where(Finding.cve_id == "CVE-2026-0002")).one()
            assert kb.risk == 20 and kb.due_at == kb.opened_at + timedelta(days=90)
            assert fix_rows(s)[0]["fix_key"] == "winget:Google.Chrome"  # highest risk first

        # A domain controller that faces the internet: 98.8 x 1.4 x 1.2.
        r = c.post(f"/devices/{dev_id}/settings", data={"criticality": "5", "internet_facing": "true"}, headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        with db.session_scope() as s:
            assert _chrome(s).risk == pytest.approx(166.0)
        page = c.get(f"/devices/{dev_id}").text
        assert "99 base x 1.4 importance x 1.2 internet facing" in page and "Due in 13 days" in page

        # Back to the default; servers default to 4, this workstation to 3.
        c.post(f"/devices/{dev_id}/settings", data={"criticality": ""}, headers=ORIGIN)
        with db.session_scope() as s:
            assert s.get(Device, dev_id).criticality is None and _chrome(s).risk == pytest.approx(98.8)

        # Push the finding past its deadline.
        with db.session_scope() as s:
            f = _chrome(s)
            f.opened_at -= timedelta(days=20)
            scoring.rescore(s, s.get(Device, dev_id))
            assert device_rows(s)[0]["overdue"] == 1 and fix_rows(s)[0]["overdue"] == 1
        assert "Overdue 6 days" in c.get(f"/devices/{dev_id}").text
        assert "Past their fix deadline" in c.get("/").text

        # Bad input goes back to the form with a message, and nothing is saved.
        form = c.get("/exceptions/new", params={"device": dev_id, "cve": CHROME_CVE})
        assert form.status_code == 200 and "1 open finding match today" in form.text
        too_long = (utcnow().date() + timedelta(days=400)).isoformat()
        r = c.post("/exceptions", data={"device": dev_id, "cve": CHROME_CVE, "reason": "false_positive", "note": "x", "expires_on": too_long},
                   headers=ORIGIN, follow_redirects=False)
        assert "/exceptions/new?" in r.headers["location"] and "error=" in r.headers["location"]
        r = c.post("/exceptions", data={"device": dev_id, "cve": CHROME_CVE, "reason": "false_positive", "note": " ", "expires_on": utcnow().date().isoformat()},
                   headers=ORIGIN, follow_redirects=False)
        assert "error=" in r.headers["location"]
        with db.session_scope() as s:
            assert s.scalars(select(FindingException)).all() == []

        # Compensating control halves the score and pauses the deadline.
        until = (utcnow().date() + timedelta(days=30)).isoformat()
        r = c.post("/exceptions", data={"device": dev_id, "cve": CHROME_CVE, "reason": "compensating_control", "note": "Site isolation policy on",
                                        "expires_on": until}, headers=ORIGIN, follow_redirects=False)
        assert r.headers["location"] == f"/devices/{dev_id}"
        with db.session_scope() as s:
            f = _chrome(s)
            assert f.exception_id is not None and f.risk == pytest.approx(49.4)
            assert device_rows(s)[0]["overdue"] == 0
        assert "Paused by exception" in c.get(f"/devices/{dev_id}").text

        # A client-wide false positive on the same CVE wins: it lowers the score most.
        r = c.post("/exceptions", data={"client": 1, "fix": "winget:Google.Chrome", "reason": "false_positive", "note": "Not installed, stale key",
                                        "expires_on": until}, headers=ORIGIN, follow_redirects=False)
        assert r.headers["location"] == "/exceptions?client=1"
        with db.session_scope() as s:
            assert _chrome(s).risk == 0
        listing = c.get("/exceptions", params={"client": 1}).text
        assert "Not installed, stale key" in listing and "Site isolation policy on" in listing

        # Ending the false positive early returns to the compensating control.
        with db.session_scope() as s:
            fp = s.scalars(select(FindingException).where(FindingException.reason == "false_positive")).one().id
        assert c.post(f"/exceptions/{fp}/revoke", headers=ORIGIN, follow_redirects=False).status_code == 303
        with db.session_scope() as s:
            assert _chrome(s).risk == pytest.approx(49.4)
        assert "Ended early by local admin" in c.get("/exceptions").text

        # When the last exception expires, the worker restores the score and the overdue deadline.
        with db.session_scope() as s:
            for e in s.scalars(select(FindingException)):
                e.expires_on = utcnow().date() - timedelta(days=1)
        with db.session_scope() as s:
            assert scoring.rescore_lapsed(s) == 1
            f = _chrome(s)
            assert f.exception_id is None and f.risk == pytest.approx(98.8) and device_rows(s)[0]["overdue"] == 1

        # Fixed, then back: the deadline starts again from the reopening.
        _post_inv(c, token, _inventory("10.0.22631.4200", "131.0.6778.86", "bbbbbbbb"))
        with db.session_scope() as s:
            findings.evaluate_pending(s)
        _post_inv(c, token, _inventory("10.0.22631.4200", "120.0.6099.71", "cccccccc"))
        with db.session_scope() as s:
            findings.evaluate_pending(s)
            f = _chrome(s)
            assert f.status == "open" and utcnow() - f.opened_at < timedelta(minutes=1) and device_rows(s)[0]["overdue"] == 0


def test_exception_scope_is_checked(session):
    with TestClient(app) as c:
        _sign_in(c)
        _, dev_id = _client(c)
        with db.session_scope() as s:
            other = tenants.create_client(s, "Other client").id
        assert c.get("/exceptions/new", params={"device": dev_id}).status_code == 400  # needs a fix or a CVE
        assert c.get("/exceptions/new", params={"device": dev_id, "cve": "not-a-cve"}).status_code == 400
        assert c.get("/exceptions/new", params={"device": dev_id, "client": other, "cve": CHROME_CVE}).status_code == 400
        assert c.get("/exceptions/new", params={"client": 999, "cve": CHROME_CVE}).status_code == 404
        # Cross-site posts are refused like every other form.
        r = c.post("/exceptions", data={"device": dev_id, "cve": CHROME_CVE, "reason": "risk_accepted", "note": "x",
                                        "expires_on": utcnow().date().isoformat()}, headers={"Origin": "https://evil.example"}, follow_redirects=False)
        assert r.status_code == 403
        # Risk accepted pauses the deadline but leaves the score alone.
        c.post("/exceptions", data={"device": dev_id, "cve": CHROME_CVE, "reason": "risk_accepted", "note": "Owner signed off",
                                    "expires_on": utcnow().date().isoformat()}, headers=ORIGIN)
        with db.session_scope() as s:
            f = _chrome(s)
            assert f.exception_id is not None and f.risk == pytest.approx(98.8)
