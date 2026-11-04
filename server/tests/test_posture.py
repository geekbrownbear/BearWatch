from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, findings, posture, scoring
from bearwatch.api import app
from bearwatch.config import get_settings
from bearwatch.intel.common import utcnow
from bearwatch.models import Device, Finding
from bearwatch.web import fix_rows

from .test_agent import GUID, _inventory, _post_inv, _seed
from .test_web import ORIGIN, _sign_in

LLMNR = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMulticast"
WDIGEST = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:UseLogonCredential"
FW_POLICY = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:EnableFirewall"
FW_LOCAL = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile:EnableFirewall"


def test_rules_file_is_valid_and_safe():
    rs = posture.ruleset()
    assert len(rs.rules) >= 15 and len(rs.hash) == 16
    assert all(posture.read_allowed(r) for r in rs.reads)
    assert {r.severity for r in rs.rules} <= scoring.POSTURE_SEVERITY.keys()
    for r in rs.rules:  # Bearium writing rules: no em or en dashes in anything a technician reads
        for text in (r.title, r.fix, r.why, r.how):
            assert chr(0x2014) not in text and chr(0x2013) not in text, r.id  # em dash, en dash
    # Text edits do not change the hash; only the reads do, so agents refetch only when needed.
    assert posture.parse(get_settings().posture_rules_path.read_text(encoding="utf-8").replace("Turn off LLMNR", "Disable LLMNR")).hash == rs.hash


def _rule(when: str, extra: str = "") -> str:
    return f'[[rule]]\nid = "t"\ntitle = "T"\ncategory = "C"\nseverity = "low"\nfix = "F"\nwhy = "W"\nhow = "H"\n{extra}\nwhen = [{when}]\n'


@pytest.mark.parametrize("when", [
    r"{ read = 'HKLM\SAM\SAM\Domains:F', op = '==', value = 1 }",  # outside the allowlist
    r"{ read = 'HKCU\Software\Policies\X:Y', op = '==', value = 1 }",
    r"{ read = 'HKLM\SOFTWARE\Policies\*:Y', op = '==', value = 1 }",
    r"{ read = 'HKLM\SOFTWARE\Policies\X:Y', op = '~=', value = 1 }",  # unknown op
    r"{ read = 'HKLM\SOFTWARE\Policies\X:Y', op = '==' }",  # no value to compare with
    r"{ read = 'HKLM\SOFTWARE\Policies\X:Y', op = 'exists', extra = 1 }",
])
def test_bad_rules_are_refused(when):
    with pytest.raises(posture.RuleError):
        posture.parse(_rule(when))


def test_conditions():
    rs = posture.parse(_rule(f"{{ read = ['{FW_POLICY}', '{FW_LOCAL}'], op = '==', value = 0, default = 1 }}"))
    run = lambda values: posture.evaluate(rs, values, is_server=False)[0].status  # noqa: E731
    assert run({FW_POLICY: None, FW_LOCAL: None}) == "pass"  # nothing set: Windows default (on)
    assert run({FW_POLICY: None, FW_LOCAL: 0}) == "fail"  # 0 is a real value, not "missing"
    assert run({FW_POLICY: 1, FW_LOCAL: 0}) == "pass"  # Group Policy wins over the local setting
    assert run({FW_POLICY: "set", FW_LOCAL: 0}) == "pass"  # non-numeric: no comparison holds
    assert run({FW_LOCAL: 0}) == "unknown"  # the agent did not read every value the rule needs

    key = r"HKLM\SYSTEM\CurrentControlSet\Services\srv"
    any_rule = posture.parse(_rule(f"{{ read = '{key}', op = 'exists' }}, {{ read = '{LLMNR}', op = '==', value = 0 }}", 'match = "any"'))
    assert posture.evaluate(any_rule, {key: True, LLMNR: None}, False)[0].status == "fail"
    assert posture.evaluate(any_rule, {key: False, LLMNR: None}, False)[0].status == "pass"
    # applies = "server" rules are skipped on workstations, and the other way round.
    server_rule = posture.parse(_rule(f"{{ read = '{key}', op = 'exists' }}", 'applies = "server"'))
    assert posture.evaluate(server_rule, {key: True}, is_server=False) == []


def _values(**overrides) -> dict:
    """Every read the rules need, as a clean workstation reports them, plus overrides."""
    v = {r: None for r in posture.ruleset().reads}
    v.update({"wsc:antivirus": 0, r"HKLM\SYSTEM\CurrentControlSet\Services\srv": False, r"HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry:Start": 4,
              r"HKLM\SOFTWARE\Microsoft\Policies\LAPS:BackupDirectory": 1, LLMNR: 0})
    v.update(overrides)
    return v


def _inv(h: str, values: dict | None) -> dict:
    inv = _inventory("10.0.22631.4200", "131.0.6778.86", h) | {"agent_version": "0.2.0"}
    if values is not None:
        inv["posture"] = {"hash": posture.ruleset().hash, "values": values}
    return inv


def _open(s) -> dict[str, Finding]:
    return {f.subject_key: f for f in s.scalars(select(Finding).where(Finding.source == "posture", Finding.status == "open"))}


def test_posture_end_to_end(session):
    key = _seed()
    with TestClient(app) as c:
        _sign_in(c)
        token = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": GUID, "hostname": "BEAR-PC01", "agent_version": "0.2.0"}).json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        rs = posture.ruleset()
        assert c.post("/api/agent/heartbeat", json={"agent_version": "0.2.0"}, headers=auth).json()["posture_hash"] == rs.hash
        assert c.post("/api/agent/posture", json={}).status_code == 401
        assert c.post("/api/agent/posture", json={}, headers=auth).json() == {"hash": rs.hash, "reads": rs.reads}

        # An old agent sends no posture: nothing is judged, and the device page says why.
        _post_inv(c, token, _inv("aaaaaaaa", None) | {"agent_version": "0.1.1"})
        with db.session_scope() as s:
            findings.evaluate_pending(s)
            assert _open(s) == {}
        assert "Settings checks need agent 0.2.0" in c.get("/devices/1").text

        # LLMNR left on, WDigest turned on, and one value from outside the allowlist.
        assert _post_inv(c, token, _inv("bbbbbbbb", _values(**{LLMNR: None, WDIGEST: 1, "HKLM\\SAM\\SAM:F": 1}))).status_code == 202
        with db.session_scope() as s:
            assert "HKLM\\SAM\\SAM:F" not in s.get(Device, 1).posture["values"]  # dropped, never stored
            findings.evaluate_pending(s)
            got = _open(s)
            assert set(got) == {"llmnr-on", "wdigest-on"}
            w = got["wdigest-on"]
            assert (w.fix_key, w.fix_label, w.cve_id) == ("posture:wdigest-on", "Turn off WDigest password caching", "wdigest-on")
            assert w.risk == pytest.approx(83.5) and w.due_at == w.opened_at + timedelta(days=14)  # critical
            assert got["llmnr-on"].risk == pytest.approx(24.0) and got["llmnr-on"].due_at == got["llmnr-on"].opened_at + timedelta(days=90)
            assert fix_rows(s)[0]["fix_key"] == "posture:wdigest-on"  # outranks the medium setting

        page = c.get("/devices/1").text
        assert "Security settings" in page and "2 of 15 checks fail" in page and "Windows setting" in page
        fix = c.get("/fix", params={"key": "posture:wdigest-on", "client": 1}).text
        assert "UseLogonCredential" in fix and "CVEs it closes" not in fix
        assert "Windows setting" in c.get("/").text

        # A compensating control on one setting halves it, like any finding.
        r = c.post("/exceptions", data={"device": 1, "fix": "posture:llmnr-on", "reason": "compensating_control", "note": "Blocked at the switch",
                                        "expires_on": "2099-01-01"}, headers=ORIGIN, follow_redirects=False)
        assert "error=" in r.headers["location"]  # 2099 is past the one-year limit
        r = c.post("/exceptions", data={"device": 1, "fix": "posture:llmnr-on", "reason": "compensating_control", "note": "Blocked at the switch",
                                        "expires_on": (utcnow().date() + timedelta(days=30)).isoformat()}, headers=ORIGIN, follow_redirects=False)
        assert r.headers["location"] == "/devices/1"
        with db.session_scope() as s:
            assert _open(s)["llmnr-on"].risk == pytest.approx(12.0)

        # WDigest turned off; the LLMNR value is missing from this upload (an agent holding an
        # older read list), so that rule cannot be judged and its finding stays open.
        values = _values(**{WDIGEST: 0})
        del values[LLMNR]
        _post_inv(c, token, _inv("cccccccc", values))
        with db.session_scope() as s:
            counts = findings.evaluate(s, s.get(Device, 1))
            assert counts["fixed"] == 1 and set(_open(s)) == {"llmnr-on"}

        # Junk values are refused: only numbers, true/false, "set" or null.
        bad = _inv("dddddddd", _values(**{LLMNR: "hunter2"}))
        assert _post_inv(c, token, bad).status_code == 422
