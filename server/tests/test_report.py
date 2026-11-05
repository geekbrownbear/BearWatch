from datetime import date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, findings, lifecycle, posture, report, tenants
from bearwatch.api import app
from bearwatch.cli import main as cli
from bearwatch.intel.common import utcnow
from bearwatch.models import Client, Device, Finding, FindingEvent

from .test_agent import _inventory, _post_inv, _seed
from .test_web import _sign_in


@pytest.mark.parametrize("build,caption,server,status,name", [
    ("10.0.19045.5000", "Windows 10 Pro", False, "ended", "Windows 10, version 22H2"),
    ("10.0.18363.1500", "Windows 10 Pro", False, "ended", "Windows 10 (build 18363)"),  # older than any listed
    ("10.0.22631.4317", "Windows 11 Pro", False, "ended", "Windows 11, version 23H2"),
    ("10.0.22631.4317", "Windows 11 Enterprise", False, "ending", "Windows 11, version 23H2"),  # ends 2026-11-10
    ("10.0.26100.9711", "Windows 11 Pro", False, "ended", "Windows 11, version 24H2"),  # Home/Pro ended 2026-10-13
    ("10.0.26100.9711", "Windows 11 Enterprise", False, "supported", "Windows 11, version 24H2"),
    ("10.0.26300.9711", "Windows 11 Pro", False, "supported", "Windows 11, version 26H2"),
    ("10.0.17763.1000", "Windows 10 Enterprise LTSC 2019", False, "unknown", "Windows 10 Enterprise LTSC 2019"),
    ("10.0.9600.1", "Windows Server 2012 R2 Standard", True, "ended", "Windows Server 2012 R2"),
    ("10.0.26100.1", "Windows Server 2025 Standard", True, "supported", "Windows Server 2025"),
    ("10.0.99999.1", "Windows 12 Pro", False, "unknown", "Build 99999"),
    (None, None, False, "unknown", "Unknown Windows version"),
])
def test_windows_support(build, caption, server, status, name):
    sup = lifecycle.support(build, caption, server, today=date(2026, 11, 5))
    assert (sup.status, sup.name) == (status, name)
    assert chr(0x2014) not in sup.label and chr(0x2013) not in sup.label


def test_month_math():
    assert report.month_bounds(date(2026, 12, 1)) == (datetime(2026, 12, 1), datetime(2027, 1, 1))
    assert report.previous_month(date(2026, 1, 15)) == date(2025, 12, 1)


def test_report_end_to_end(session, tmp_path):
    key = _seed()
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": "0f8fad5b-d9cb-469f-a165-70867728950e",
                                              "hostname": "BEAR-PC01", "agent_version": "0.3.0"})
        token = r.json()["token"]
        # An old build with missing updates and an old Chrome: Windows and app findings.
        assert _post_inv(c, token, _inventory("10.0.22631.4000", "119.0.6045.105", "inv-0001")).status_code == 202
        with db.session_scope() as s:
            dev = s.scalars(select(Device)).one()
            findings.evaluate(s, dev)
            client_id = s.scalars(select(Client)).one().id
            # Backdate one fix into last month, finished after its deadline, so the month has history.
            f = s.scalars(select(Finding)).first()
            month = report.previous_month()
            # Found on the 1st, known exploited (14 days), fixed on the 20th: late. It is open again
            # now with a fresh deadline, which must not make that old fix look on time.
            s.add(FindingEvent(finding_id=f.id, device_id=dev.id, event="found", at=datetime(month.year, month.month, 1)))
            s.add(FindingEvent(finding_id=f.id, device_id=dev.id, event="fixed", at=datetime(month.year, month.month, 20)))
            f.exploit_tier = 1
            f.due_at = utcnow() + timedelta(days=14)

        with db.session_scope() as s:
            rep = report.build(s, client_id, month)
            assert rep.devices == 1 and rep.open_fixes >= 1 and rep.fixed == 1 and rep.on_time_rate == 0
            assert len(rep.trend) == 6 and rep.trend[-1]["month"] == month
            # Windows 11 23H2 Pro is out of support: deducted, and the checklist says so.
            assert any("no longer gets security updates" in t for _, t in rep.deductions)
            item = next(i for i in rep.checklist if i.title.startswith("Every PC runs"))
            assert item.status == "fail"
            # No sensor: the network item is "not yet", not a pass.
            assert next(i for i in rep.checklist if "network" in i.title).status == "unknown"
            # This agent sent no settings values: the settings items are "not checked", never a pass.
            assert next(i for i in rep.checklist if i.title.startswith("Antivirus")).status == "unknown"
            assert not any(i.status == "pass" and i.title.startswith(("Windows Firewall", "Local admin")) for i in rep.checklist)
            # Plurals read right.
            assert all(" 1 updates" not in t and " 1 PCs" not in t for _, t in rep.deductions)

        with db.session_scope() as s:
            dev = s.get(Device, dev.id)
            # A posture report that read nothing the rules need: still "not checked", never a pass.
            dev.posture = {"hash": "x" * 16, "values": {}}
        with db.session_scope() as s:
            checks = {i.title: i for i in report.build(s, client_id, month).checklist}
            assert checks["Windows Firewall is on"].status == "unknown"
            assert checks["Local admin passwords are unique and rotated"].status == "unknown"
        with db.session_scope() as s:
            dev = s.get(Device, dev.id)
            # Every read present but unset: Windows defaults, so the firewall is on and LAPS is missing.
            dev.posture = {"hash": "x" * 16, "values": {k: None for k in posture.ruleset().reads}}
            f = Finding(device_id=dev.id, source="posture", subject_key="laps-missing", subject="LAPS is not set up",
                        cve_id="laps-missing", fix_key="posture:laps-missing", fix_label="Set up Windows LAPS", status="open",
                        first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1), opened_at=datetime(2026, 1, 1))
            s.add(f)
        with db.session_scope() as s:
            rep = report.build(s, client_id, month)
            checks = {i.title: i for i in rep.checklist}
            assert checks["Windows Firewall is on"].status == "pass"
            assert checks["Local admin passwords are unique and rotated"].status == "fail"
            assert checks["Local admin passwords are unique and rotated"].detail == "1 PC has no LAPS."
            assert rep.settings == [{"rule": "laps-missing", "title": "LAPS is not set up", "devices": 1}]
            dev_id = dev.id
            assert rep.score == 100 - sum(p for p, _ in rep.deductions) and rep.grade in "ABCDF"
            html = report.render_html(rep)
            for text in ("Monthly security report", "Bearium Networks", "Cyber insurance checklist", "(407) 917-1321",
                         "Windows 11, version 23H2", "How the grade was set"):
                assert text in html, text
            # Bearium writing rules for anything a client reads.
            assert chr(0x2014) not in html and chr(0x2013) not in html
            assert "engineer" not in html.lower()

        _sign_in(c)
        page = c.get(f"/clients/{client_id}/report?month={month:%Y-%m}")
        assert page.status_code == 200 and "Cyber insurance checklist" in page.text and "/static/report-logo.svg" in page.text
        assert c.get(f"/clients/{client_id}/report?month=junk").status_code == 400
        assert c.get("/clients/999/report").status_code == 404
        assert "Monthly report" in c.get(f"/clients/{client_id}").text
        assert "Out of support since" in c.get(f"/devices/{dev_id}").text

    out = tmp_path / "r.html"
    assert cli(["report", str(client_id), "--month", f"{month:%Y-%m}", "--out", str(out), "--html"]) == 0
    assert "Cyber insurance checklist" in out.read_text(encoding="utf-8")


def test_empty_client_report(session):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Empty")
        rep = report.build(s, c.id, date(2026, 10, 1), now=datetime(2026, 11, 5))
        assert (rep.devices, rep.score, rep.grade) == (0, 100, "A")
        assert all(i.status in ("unknown", "pass") for i in rep.checklist)
        assert "No PCs report to BearWatch yet." in report.render_html(rep)


@pytest.mark.skipif(not report.pdf_available(), reason="WeasyPrint and Pango are not installed here")
def test_pdf_renders(session):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Pdf Test")
        pdf = report.render_pdf(report.build(s, c.id, date(2026, 10, 1)))
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000


def test_grade_penalties_are_capped(session):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Capped")
        rep = report.build(s, c.id, date(2026, 10, 1), now=datetime(2026, 11, 5))
    each, most = report.PENALTIES["exploited"]
    assert most < each * 10  # ten exploited fixes cost the cap, not 150 points
    assert timedelta(hours=24) == report.SILENT
    assert rep.deductions == []


def test_unknown_windows_support_is_not_a_yes(session):
    with db.session_scope() as s:
        c = tenants.create_client(s, "Ltsc")
        site, _ = tenants.create_site(s, c, "Plant")
        s.add(Device(site_id=site.id, machine_guid="a" * 32, hostname="LINE-1", token_hash="a" * 64, enrolled_at=utcnow(),
                     last_seen=utcnow(), os_build="10.0.17763.1000", os_caption="Windows 10 Enterprise LTSC 2019"))
        s.flush()
        item = next(i for i in report.build(s, c.id, date(2026, 10, 1)).checklist if i.title.startswith("Every PC runs"))
    assert item.status == "unknown" and item.detail == "Support dates are unknown for 1 PC."
