import json
from datetime import timedelta

import httpx
import pytest
import respx
from sqlalchemy import select

from bearwatch import config, db, halo, tenants
from bearwatch.cli import main as cli
from bearwatch.intel.common import utcnow
from bearwatch.models import Device, Finding, HaloTicket

HALO = "https://halo.example.test"


def _settings(monkeypatch, **env):
    base = {"BEARWATCH_HALO_URL": HALO, "BEARWATCH_HALO_CLIENT_ID": "cid", "BEARWATCH_HALO_CLIENT_SECRET": "secret",
            "BEARWATCH_PUBLIC_URL": "https://bearwatch.example.test"}
    for k, v in {**base, **env}.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()


def _setup(s, halo_id=55):
    c = tenants.create_client(s, "Lab")
    c.halo_client_id = halo_id
    site, _ = tenants.create_site(s, c, "Office")
    devs = []
    for i, name in enumerate(["PC-A", "PC-B"]):
        d = Device(site_id=site.id, machine_guid=f"{i:032x}", hostname=name, token_hash=f"{i:064x}", enrolled_at=utcnow())
        s.add(d)
        devs.append(d)
    s.flush()
    return c, devs


def _finding(s, dev, fix_key, cve, tier=4, risk=10.0, due_days=30, status="open"):
    now = utcnow()
    f = Finding(device_id=dev.id, source="os", subject_key="windows", subject="Windows", cve_id=cve, fix_key=fix_key,
                fix_label=f"Install {fix_key}", status=status, exploit_tier=tier, risk=risk, first_seen=now, last_seen=now,
                opened_at=now, due_at=now + timedelta(days=due_days))
    s.add(f)
    s.flush()
    return f


def test_off_until_configured(session, monkeypatch, capsys):
    config.get_settings.cache_clear()
    assert halo.api_from_settings() is None and not halo.configured()
    assert cli(["halo", "sync"]) == 2


def test_dry_run_sends_and_saves_nothing(session, monkeypatch, capsys):
    _settings(monkeypatch)  # dry run is the default
    with db.session_scope() as s:
        c, devs = _setup(s)
        _finding(s, devs[0], "kb:5070001", "CVE-2026-1001", tier=1, risk=90)
        _finding(s, devs[0], "app:minor", "CVE-2026-1002", risk=5)  # not serious enough
    assert cli(["halo", "sync"]) == 0
    out = capsys.readouterr().out
    assert "Dry run" in out and "would create BearWatch: Install kb:5070001" in out and "app:minor" not in out
    assert session.scalars(select(HaloTicket)).all() == []
    assert cli(["halo", "client", str(c.id), "none"]) == 0


@respx.mock
def test_ticket_lifecycle(session, monkeypatch):
    _settings(monkeypatch, BEARWATCH_HALO_DRY_RUN="false", BEARWATCH_HALO_TICKET_TYPE_ID="31")
    token = respx.post(f"{HALO}/auth/token").mock(return_value=httpx.Response(200, json={"access_token": "t0k", "expires_in": 3600}))
    next_id = iter(range(101, 200))
    posted: list[tuple[str, list]] = []

    def on_tickets(request):
        body = json.loads(request.content)
        posted.append(("tickets", body))
        assert request.headers["authorization"] == "Bearer t0k"
        return httpx.Response(201, json=[{**body[0], "id": body[0].get("id") or next(next_id)}])

    def on_actions(request):
        posted.append(("actions", json.loads(request.content)))
        return httpx.Response(201, json=[{"id": 1}])

    respx.post(f"{HALO}/api/tickets").mock(side_effect=on_tickets)
    respx.post(f"{HALO}/api/actions").mock(side_effect=on_actions)
    status = respx.get(f"{HALO}/api/tickets/101").mock(return_value=httpx.Response(200, json={"id": 101, "status_id": 2}))

    api = halo.api_from_settings()
    assert isinstance(api, halo.HaloApi)
    with db.session_scope() as s:
        c, devs = _setup(s)
        _finding(s, devs[0], "kb:5070001", "CVE-2026-1001", tier=1, risk=90)
        _finding(s, devs[0], "app:late", "CVE-2026-1003", risk=20, due_days=-1)  # overdue: ticket
        _finding(s, devs[1], "app:minor", "CVE-2026-1002", risk=5)  # no ticket
        other = tenants.create_client(s, "No Halo id")
        other_site, _ = tenants.create_site(s, other, "X")
        d = Device(site_id=other_site.id, machine_guid="f" * 32, hostname="Z", token_hash="f" * 64, enrolled_at=utcnow())
        s.add(d)
        s.flush()
        _finding(s, d, "kb:5070001", "CVE-2026-1001", tier=1, risk=90)  # client without a Halo id: ignored
        assert halo.sync(s, api) == 2
    creates = [b[0] for kind, b in posted if kind == "tickets"]
    assert {t["summary"] for t in creates} == {"BearWatch: Install kb:5070001", "BearWatch: Install app:late"}
    kb = next(t for t in creates if "kb:" in t["summary"])
    assert kb["client_id"] == 55 and kb["tickettype_id"] == 31
    assert "PC-A" in kb["details"] and "known exploited" in kb["details"] and "https://bearwatch.example.test/fix?key=kb:5070001" in kb["details"]
    assert token.call_count == 1  # the token is reused

    # Nothing changed: nothing sent.
    posted.clear()
    with db.session_scope() as s:
        assert halo.sync(s, api) == 0
    assert posted == []

    # The same fix is now needed on a second PC: the ticket is updated with a private note.
    with db.session_scope() as s:
        _finding(s, s.scalars(select(Device).where(Device.hostname == "PC-B")).one(), "kb:5070001", "CVE-2026-1001", tier=1, risk=90)
        assert halo.sync(s, api) == 1
    assert [k for k, _ in posted] == ["tickets", "actions"]
    assert posted[0][1][0]["id"] == 101 and "PC-B" in posted[0][1][0]["details"]
    assert posted[1][1][0]["hiddenfromuser"] is True and posted[1][1][0]["outcome"] == "Private Note"

    # Every PC fixed: closed with a note.
    posted.clear()
    with db.session_scope() as s:
        for f in s.scalars(select(Finding).where(Finding.fix_key == "kb:5070001")):
            f.status = "fixed"
        assert halo.sync(s, api) == 1
        row = s.scalars(select(HaloTicket).where(HaloTicket.fix_key == "kb:5070001", HaloTicket.client_id == c.id)).one()
        assert row.status == "closed" and row.closed_at is not None
    assert posted[0][0] == "actions" and posted[1] == ("tickets", [{"id": 101, "status_id": 9}])

    # It comes back: a new ticket, not the closed one.
    posted.clear()
    with db.session_scope() as s:
        for f in s.scalars(select(Finding).where(Finding.fix_key == "kb:5070001")):
            f.status = "open"
        halo.sync(s, api)
        row = s.scalars(select(HaloTicket).where(HaloTicket.fix_key == "kb:5070001", HaloTicket.client_id == c.id)).one()
        assert row.status == "open" and row.halo_id != 101
    assert status.call_count == 1


@respx.mock
def test_closed_in_halo_and_errors(session, monkeypatch):
    _settings(monkeypatch, BEARWATCH_HALO_DRY_RUN="false")
    respx.post(f"{HALO}/auth/token").mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    tickets = respx.post(f"{HALO}/api/tickets")
    tickets.mock(return_value=httpx.Response(201, json={"id": 300}))  # a single object is fine too
    api = halo.api_from_settings()
    with db.session_scope() as s:
        c, devs = _setup(s)
        _finding(s, devs[0], "kb:1", "CVE-2026-0001", tier=1, risk=90)
        assert halo.sync(s, api) == 1
        assert s.scalars(select(HaloTicket)).one().halo_id == 300

    # A technician closed it in Halo, but the PCs still need the fix: closed here, new ticket next pass.
    respx.get(f"{HALO}/api/tickets/300").mock(return_value=httpx.Response(200, json={"id": 300, "status_id": 9}))
    with db.session_scope() as s:
        _finding(s, devs[1], "kb:1", "CVE-2026-0001", tier=1, risk=90)
        halo.sync(s, api)
        assert s.scalars(select(HaloTicket)).one().status == "closed"

    # Halo errors are recorded on the row and don't stop the pass.
    tickets.mock(return_value=httpx.Response(500, text="boom"))
    with db.session_scope() as s:
        assert halo.sync(s, api) == 0
        row = s.scalars(select(HaloTicket)).one()
        assert "HTTP 500" in row.last_error

    # Bad credentials: a clear error, never the secret.
    respx.post(f"{HALO}/auth/token").mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))
    fresh = halo.HaloApi(HALO, "cid", "secret")
    with pytest.raises(halo.HaloError) as e:
        fresh.create_ticket({"summary": "x"})
    assert "secret" not in str(e.value)


def test_empty_compose_variables_mean_unset(monkeypatch):
    _settings(monkeypatch, BEARWATCH_HALO_TICKET_TYPE_ID="", BEARWATCH_HALO_DRY_RUN="")
    cfg = config.get_settings()
    assert cfg.halo_ticket_type_id is None and cfg.halo_dry_run is True
    config.get_settings.cache_clear()


def test_summary_is_short():
    g = halo.Group("k", "Update " + "Very Long Application Name " * 5, 4, 60.0, None, ["A"], [])
    assert len(halo._summary(g)) <= halo.SUMMARY_MAX and halo._summary(g).endswith("...")
