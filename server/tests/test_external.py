from datetime import date, timedelta

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, external, report, tenants
from bearwatch.api import app
from bearwatch.cli import main as cli
from bearwatch.intel.common import utcnow
from bearwatch.models import ExternalIssue, ExternalTarget, Kev

from .test_web import ORIGIN, _sign_in

IP = "8.8.4.4"  # every lookup in these tests is mocked; nothing is sent to it


@pytest.mark.parametrize("raw,expect", [
    ("8.8.4.4", ("ip", "8.8.4.4")),
    (" Example.COM. ", ("domain", "example.com")),
    ("https://example.com/path", ("domain", "example.com")),
    ("mail.example.co.uk", ("domain", "mail.example.co.uk")),
])
def test_normalize(raw, expect):
    assert external.normalize(raw) == expect


@pytest.mark.parametrize("raw", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "203.0.113.10", "not a host", "exa mple.com", ""])
def test_normalize_refuses(raw):
    with pytest.raises(ValueError):
        external.normalize(raw)


def _doh(spf="v=spf1 include:spf.protection.outlook.com -all", dmarc="v=DMARC1; p=quarantine", ad=True):
    def handler(request):
        name = request.url.params["name"]
        txt = dmarc if name.startswith("_dmarc.") else spf
        answer = [{"name": name, "type": 16, "data": f'"{txt}"'}] if txt else []
        return httpx.Response(200, json={"Status": 0, "AD": ad, "Answer": answer})
    return handler


@respx.mock
def test_checks_and_issue_lifecycle(session):
    with db.session_scope() as s:
        s.add(Kev(cve_id="CVE-2019-0708", source="cisa", date_added=date(2019, 11, 3)))
        c = tenants.create_client(s, "Lab")
        s.add(ExternalTarget(client_id=c.id, kind="ip", value=IP, created_at=utcnow()))
        s.add(ExternalTarget(client_id=c.id, kind="domain", value="example.com", created_at=utcnow()))
        client_id = c.id

    idb = respx.get(f"https://internetdb.shodan.io/{IP}")
    idb.mock(return_value=httpx.Response(200, json={"ip": IP, "ports": [443, 3389], "vulns": ["CVE-2019-0708", "CVE-2020-0001"],
                                                    "hostnames": [], "tags": [], "cpes": []}))
    respx.get(external.DOH).mock(side_effect=_doh(spf=None, dmarc="v=DMARC1; p=none", ad=False))
    with db.session_scope() as s, httpx.Client() as http:
        for t in external.due(s):
            external.check(s, t, http, cert_days_left=lambda d: 5)
    open_ = {i.check_id: i for i in session.scalars(select(ExternalIssue).where(ExternalIssue.status == "open"))}
    assert set(open_) == {"port-3389", "shodan-cves", "spf-missing", "dmarc-monitor-only", "dnssec-off", "cert-expiring"}
    assert open_["port-3389"].severity == "critical" and open_["shodan-cves"].severity == "high"  # one is known exploited
    assert "CVE-2019-0708" in open_["shodan-cves"].detail

    # Not due again for a week.
    with db.session_scope() as s:
        assert external.due(s) == []
        assert external.due(s, now=utcnow() + timedelta(days=8)) != []

    # A week later: RDP closed, SMB opened (new), DNS fixed, but the DNS lookup for DMARC fails:
    # a failed check changes nothing.
    idb.mock(return_value=httpx.Response(200, json={"ip": IP, "ports": [443, 445], "vulns": [], "hostnames": [], "tags": []}))
    respx.get(external.DOH).mock(side_effect=_doh())
    with db.session_scope() as s, httpx.Client() as http:
        for t in s.scalars(select(ExternalTarget)):
            if t.kind == "ip":
                t.first_checked_at -= timedelta(days=7)
            external.check(s, t, http, cert_days_left=lambda d: 80, now=utcnow() + timedelta(days=7))
    session.expire_all()
    open_ = {i.check_id for i in session.scalars(select(ExternalIssue).where(ExternalIssue.status == "open"))}
    assert open_ == {"port-445"}
    ip_t = session.scalars(select(ExternalTarget).where(ExternalTarget.kind == "ip")).one()
    assert external.new_ports(ip_t, now=utcnow() + timedelta(days=7)) == [445]

    respx.get(external.DOH).mock(return_value=httpx.Response(503))
    with db.session_scope() as s, httpx.Client() as http:
        t = s.scalars(select(ExternalTarget).where(ExternalTarget.kind == "domain")).one()
        external.check(s, t, http, cert_days_left=lambda d: 1)
        assert "HTTP 503" in t.last_error
    assert session.scalars(select(ExternalIssue).where(ExternalIssue.check_id == "cert-expiring")).one().status == "fixed"

    # The report: SMB open to the internet fails the remote access item; email is protected.
    with db.session_scope() as s:
        checks = {i.title: i for i in report.build(s, client_id, date(2026, 10, 1)).checklist}
    assert checks["Remote access and file sharing are closed to the internet"].status == "fail"
    # Its last DNS check failed, so email protection is unverified: "not yet", never "yes".
    assert checks["Email is protected from spoofing (SPF and DMARC)"].status == "unknown"


@respx.mock
def test_cloudflare_edge_ports_are_not_the_clients(session):
    respx.get(f"https://internetdb.shodan.io/{IP}").mock(return_value=httpx.Response(200, json={
        "ports": [80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 8080, 8443], "vulns": [], "hostnames": [], "tags": ["cdn"]}))
    with httpx.Client() as http:
        snap, found = external.check_ip(http, IP, set())
    assert snap["ports"] == [80, 443] and found == []


@respx.mock
def test_nothing_known_is_not_an_error(session):
    respx.get(f"https://internetdb.shodan.io/{IP}").mock(return_value=httpx.Response(404, json={"detail": "No information available"}))
    with httpx.Client() as http:
        snap, found = external.check_ip(http, IP, set())
    assert snap["ports"] == [] and found == []


def test_pages_and_cli(session, capsys):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Lab")
        client_id = c.id
    with TestClient(app) as tc:
        _sign_in(tc)
        r = tc.post(f"/clients/{client_id}/external", data={"value": "Example.com"}, headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        r = tc.post(f"/clients/{client_id}/external", data={"value": "192.168.1.1"}, headers=ORIGIN, follow_redirects=False)
        assert "error=" in r.headers["location"]
        assert tc.post(f"/clients/{client_id}/external", data={"value": "example.com"}, headers=ORIGIN, follow_redirects=False).status_code == 303
        page = tc.get(f"/clients/{client_id}").text
        assert "Seen from the internet" in page and "example.com" in page and "Waiting for the first check" in page
        t = session.scalars(select(ExternalTarget)).one()  # the duplicate was ignored
        assert tc.post(f"/external/{t.id}/delete", headers=ORIGIN, follow_redirects=False).status_code == 303
    assert session.scalars(select(ExternalTarget)).all() == []
    assert cli(["external", "add", str(client_id), IP]) == 0
    assert cli(["external", "add", str(client_id), "10.1.1.1"]) == 2
    assert cli(["external", "list"]) == 0 and IP in capsys.readouterr().out

    # Not listed yet: the report says "not yet", never "yes".
    with db.session_scope() as s:
        checks = {i.title: i for i in report.build(s, client_id, date(2026, 10, 1)).checklist}
    assert checks["Remote access and file sharing are closed to the internet"].status == "unknown"
    assert checks["Email is protected from spoofing (SPF and DMARC)"].status == "unknown"


@respx.mock
def test_failed_measurements_are_not_fixes(session):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Lab")
        dom = ExternalTarget(client_id=c.id, kind="domain", value="example.com", created_at=utcnow())
        ip = ExternalTarget(client_id=c.id, kind="ip", value=IP, created_at=utcnow())
        s.add_all([dom, ip])
        s.flush()
        client_id = c.id
        respx.get(external.DOH).mock(side_effect=_doh(spf="v=spf1 +all"))
        with httpx.Client() as http:
            external.check(s, dom, http, cert_days_left=lambda d: 3)
        assert {i.check_id for i in s.scalars(select(ExternalIssue))} == {"spf-allows-all", "cert-expiring"}

        # SERVFAIL comes back as HTTP 200: a failed lookup, not "no SPF". Nothing changes.
        respx.get(external.DOH).mock(return_value=httpx.Response(200, json={"Status": 2, "AD": False}))
        with httpx.Client() as http:
            external.check(s, dom, http, cert_days_left=lambda d: 3)
        assert "status 2" in dom.last_error
        assert {(i.check_id, i.status) for i in s.scalars(select(ExternalIssue))} == {("spf-allows-all", "open"), ("cert-expiring", "open")}

        # DNS works again but the TLS connection fails: the certificate issue stays open.
        respx.get(external.DOH).mock(side_effect=_doh())
        with httpx.Client() as http:
            external.check(s, dom, http, cert_days_left=lambda d: None)
        states = {i.check_id: i.status for i in s.scalars(select(ExternalIssue))}
        assert states == {"spf-allows-all": "fixed", "cert-expiring": "open"} and dom.snapshot["cert_days_left"] == 3

        # A target whose first check failed can't let an item pass.
        respx.get(f"https://internetdb.shodan.io/{IP}").mock(return_value=httpx.Response(500))
        with httpx.Client() as http:
            external.check(s, ip, http)
        assert ip.snapshot is None and ip.last_error
        checks = {i.title: i for i in report.build(s, client_id, date(2026, 10, 1)).checklist}
    assert checks["Remote access and file sharing are closed to the internet"].status == "unknown"
    assert checks["Remote access and file sharing are closed to the internet"].detail == f"Not checked yet: {IP}."
    assert checks["Email is protected from spoofing (SPF and DMARC)"].status == "pass"
