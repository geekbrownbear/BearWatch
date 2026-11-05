import gzip
import json
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import db, sensor, tenants
from bearwatch.api import app
from bearwatch.cli import main as cli
from bearwatch.models import Device, NetworkHost, NetworkIssue, Site

from .test_agent import _inventory, _post_inv
from .test_web import ORIGIN, _sign_in

GUID_A = "0f8fad5b-d9cb-469f-a165-70867728950e"
GUID_B = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
SENSOR_MAC, PRINTER_MAC, LAPTOP_MAC = "bc:24:11:9e:d0:af", "00:1b:a9:12:34:56", "3c:22:fb:aa:bb:cc"
REDIS = {"id": "PIS-0005", "port": 6379, "title": "Redis accepts commands without a password", "cvss": 9.3,
         "evidence": "PING answered +PONG", "solution": "Set requirepass, or bind Redis to localhost."}


def _host(ip, mac, name=None, ports=(), issues=()):
    return {"ip": ip, "mac": mac, "vendor": None, "names": {"dns": None, "netbios": name, "mdns": None, "upnp": None},
            "workgroup": None, "rtt_ms": 0.5, "ports": [{"port": p, "service": None, "banner": None} for p in ports], "issues": list(issues)}


def _scan(*hosts):
    return {"agent_version": "0.3.0", "started_at": "2026-11-05T09:00:00Z", "duration_ms": 41000,
            "networks": [{"interface": "Ethernet", "cidr": "172.26.71.0/24", "address": "172.26.71.221", "gateway": None}],
            "hosts": list(hosts)}


def _post_scan(c, token, body):
    raw = gzip.compress(json.dumps(body).encode())
    return c.post("/api/agent/sensor", content=raw, headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip",
                                                              "Content-Type": "application/json"})


def _enroll(c, key, guid, hostname):
    r = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": guid, "hostname": hostname, "agent_version": "0.3.0"})
    assert r.status_code == 200, r.text
    return r.json()["device_id"], r.json()["token"]


def _hb(c, token):
    r = c.post("/api/agent/heartbeat", json={"agent_version": "0.3.0"}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    return r.json()


def _hosts(s) -> dict[str, NetworkHost]:
    s.expire_all()
    return {h.ip: h for h in s.scalars(select(NetworkHost))}


def _issues(s) -> list[NetworkIssue]:
    s.expire_all()
    return s.scalars(select(NetworkIssue)).all()


def _age_baseline(s, days=1):
    """Pretend the baseline scan happened a while ago, so the next scan can find new hosts."""
    site = s.scalars(select(Site)).one()
    site.sensor_first_scan_at -= timedelta(days=days)
    for h in s.scalars(select(NetworkHost)):
        h.first_seen -= timedelta(days=days)
    s.commit()


def test_sensor_end_to_end(session):
    with db.session_scope() as s:
        client = tenants.create_client(s, "Lab")
        site, key = tenants.create_site(s, client, "Office")
        site_id = site.id
    with TestClient(app) as c:
        sensor_id, sensor_tok = _enroll(c, key, GUID_A, "W11-DEV01")
        laptop_id, laptop_tok = _enroll(c, key, GUID_B, "LAPTOP7")

        # No sensor yet: nobody is told to scan, and uploads are refused.
        assert _hb(c, sensor_tok)["sensor"] is None
        assert _post_scan(c, sensor_tok, _scan()).status_code == 409

        assert cli(["site", "sensor", str(site_id), str(sensor_id)]) == 0
        assert _hb(c, sensor_tok)["sensor"] == {"interval_minutes": 240}
        assert _hb(c, laptop_tok)["sensor"] is None
        assert _post_scan(c, laptop_tok, _scan()).status_code == 409  # only the chosen PC
        assert c.post("/api/agent/sensor", content=b"x", headers={"Authorization": "Bearer nope"}).status_code == 401

        # The sensor PC reports its MAC in its inventory; the laptop is matched by name instead.
        inv = _inventory("10.0.22631.4317", "131.0.6778.86", "inv-a-0001")
        inv["hostname"], inv["macs"] = "W11-DEV01", [SENSOR_MAC.upper().replace(":", "-"), "00:00:00:00:00:00"]
        assert _post_inv(c, sensor_tok, inv).status_code == 202

        # Baseline scan.
        r = _post_scan(c, sensor_tok, _scan(
            _host("172.26.71.221", SENSOR_MAC, "W11-DEV01", ports=[135, 445]),
            _host("172.26.71.30", PRINTER_MAC, "HP-PRINTER", ports=[80, 9100]),
            _host("172.26.71.44", LAPTOP_MAC, "laptop7"),
            _host("172.26.71.244", "bc:24:11:41:f4:f1", ports=[22, 6379], issues=[REDIS]),
            _host("172.26.71.244", "bc:24:11:41:f4:f1"),  # seen twice (two adapters): kept once
        ))
        assert r.status_code == 200 and r.json() == {"hosts": 4}
        hosts = _hosts(session)
        assert hosts["172.26.71.221"].device_id == sensor_id  # by MAC
        assert hosts["172.26.71.44"].device_id == laptop_id  # by name, case-insensitive
        # Next scan the name lookup fails for the laptop: same MAC, so it stays linked.
        r = _post_scan(c, sensor_tok, _scan(_host("172.26.71.44", LAPTOP_MAC)))
        assert _hosts(session)["172.26.71.44"].device_id == laptop_id
        assert hosts["172.26.71.30"].device_id is None and hosts["172.26.71.30"].name == "HP-PRINTER"
        site = session.get(Site, site_id)
        assert not any(sensor.is_new(h, site) for h in hosts.values())  # the baseline is never "new"
        (i,) = _issues(session)
        assert (i.check_id, i.port, i.status) == ("PIS-0005", 6379, "open")

        # A week later: a camera appears, Redis gets a password, the printer is off.
        _age_baseline(session)
        r = _post_scan(c, sensor_tok, _scan(
            _host("172.26.71.221", SENSOR_MAC, "W11-DEV01"),
            _host("172.26.71.50", "9c:8e:cd:01:02:03", ports=[554]),
            _host("172.26.71.244", "bc:24:11:41:f4:f1", ports=[22, 6379]),
        ))
        assert r.status_code == 200
        hosts, site = _hosts(session), session.get(Site, site_id)
        assert sensor.is_new(hosts["172.26.71.50"], site)
        assert not sensor.is_new(hosts["172.26.71.30"], site)
        (i,) = _issues(session)
        assert i.status == "fixed" and i.fixed_at is not None

        # Redis loses its password again: the same issue reopens. Then a scan reaches the host but
        # the Redis check times out: the issue stays open, since no answer is not a fix.
        r = _post_scan(c, sensor_tok, _scan(_host("172.26.71.244", "bc:24:11:41:f4:f1", ports=[6379], issues=[REDIS])))
        r = _post_scan(c, sensor_tok, _scan({**_host("172.26.71.244", "bc:24:11:41:f4:f1", ports=[22, 6379]), "unchecked_ports": [6379]}))
        assert r.status_code == 200
        (i,) = _issues(session)
        assert i.status == "open"
        bad = _scan({**_host("172.26.71.244", "bc:24:11:41:f4:f1"), "unchecked_ports": [70000]})
        assert _post_scan(c, sensor_tok, bad).status_code == 422
        # Redis loses its password again: the same issue reopens. The printer is still off, so
        # nothing about it changes.
        r = _post_scan(c, sensor_tok, _scan(_host("172.26.71.244", "bc:24:11:41:f4:f1", ports=[6379], issues=[REDIS])))
        (i,) = _issues(session)
        assert i.status == "open" and i.fixed_at is None

        # A device without a visible MAC (behind a router) is kept by IP; a bad MAC is dropped, not fatal.
        r = _post_scan(c, sensor_tok, _scan(_host("10.9.0.5", None), _host("10.9.0.6", "zz:zz")))
        assert r.status_code == 200
        keys = {h.key for h in _hosts(session).values()}
        assert {"ip:10.9.0.5", "ip:10.9.0.6"} <= keys

        # Junk is refused before anything is stored.
        bad = _scan(_host("172.26.71.9", None))
        bad["hosts"][0]["ports"] = [{"port": 70000}]
        assert _post_scan(c, sensor_tok, bad).status_code == 422
        assert _post_scan(c, sensor_tok, {"hosts": "x"}).status_code == 422

        # Pages.
        _sign_in(c)
        page = c.get(f"/sites/{site_id}/network")
        assert page.status_code == 200
        for text in ("HP-PRINTER", "Redis accepts commands without a password", "New", "W11-DEV01"):
            assert text in page.text, text
        dev_page = c.get(f"/devices/{sensor_id}").text
        assert "This PC is the network sensor for Office" in dev_page and "172.26.71.221" in dev_page
        assert "New on a network this week" in c.get("/").text
        assert "Network issues" in c.get(f"/clients/{site.client_id}").text
        admin = c.get("/admin").text
        assert "Network sensor" in admin and f'value="{sensor_id}" selected' in admin

        # Mark the camera as known: no longer new.
        cam = _hosts(session)["172.26.71.50"]
        assert c.post(f"/network/hosts/{cam.id}/known", headers=ORIGIN, follow_redirects=False).status_code == 303
        assert not sensor.is_new(_hosts(session)["172.26.71.50"], session.get(Site, site_id))

        # The laptop's agent reports its MAC later: the host it matched by name keeps the link,
        # and a host seen only by that MAC on another site of the same client is linked too.
        inv_b = _inventory("10.0.22631.4317", "131.0.6778.86", "inv-b-0001")
        inv_b["hostname"], inv_b["macs"] = "LAPTOP7", [LAPTOP_MAC]
        assert _post_inv(c, laptop_tok, inv_b).status_code == 202
        assert _hosts(session)["172.26.71.44"].device_id == laptop_id

        # Switching the sensor off from the admin page stops the plan and refuses uploads.
        r = c.post(f"/admin/sites/{site_id}/sensor", data={"device_id": ""}, headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        assert _hb(c, sensor_tok)["sensor"] is None
        assert _post_scan(c, sensor_tok, _scan()).status_code == 409
        # A PC from another site can't be picked.
        with db.session_scope() as s:
            other, _ = tenants.create_site(s, tenants.create_client(s, "Other"), "Other")
            other_id = other.id
        r = c.post(f"/admin/sites/{other_id}/sensor", data={"device_id": str(sensor_id)}, headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303 and "error=" in r.headers["location"]


def test_a_scan_of_no_network_is_not_a_scan(session):
    with db.session_scope() as s:
        client = tenants.create_client(s, "Lab")
        site, _ = tenants.create_site(s, client, "Office")
        empty = _scan()
        empty["networks"] = []
        assert sensor.store(s, site, sensor.Report.model_validate(empty)) == 0
        assert site.sensor_scan_at is None and site.sensor_first_scan_at is None


def test_new_sensor_resets_the_baseline(session):
    with db.session_scope() as s:
        client = tenants.create_client(s, "Lab")
        site, _ = tenants.create_site(s, client, "Office")
        a = Device(site_id=site.id, machine_guid=GUID_A, hostname="A", token_hash="a" * 64, enrolled_at=site.created_at)
        b = Device(site_id=site.id, machine_guid=GUID_B, hostname="B", token_hash="b" * 64, enrolled_at=site.created_at)
        s.add_all([a, b])
        s.flush()
        tenants.set_sensor(s, site, a)
        sensor.store(s, site, sensor.Report.model_validate(_scan(_host("10.0.0.2", PRINTER_MAC))))
        assert site.sensor_first_scan_at is not None
        tenants.set_sensor(s, site, a)  # unchanged: baseline kept
        assert site.sensor_first_scan_at is not None
        tenants.set_sensor(s, site, b)  # another PC, maybe another subnet: next scan is the baseline
        assert site.sensor_first_scan_at is None and site.sensor_device_id == b.id
        sensor.store(s, site, sensor.Report.model_validate(_scan(_host("10.1.0.9", LAPTOP_MAC))))
        hosts = {h.ip: h for h in s.scalars(select(NetworkHost))}
        assert not sensor.is_new(hosts["10.1.0.9"], site)


def test_addresses_of_one_host_are_merged_and_shared_names_link_nothing(session):
    with db.session_scope() as s:
        client = tenants.create_client(s, "Lab")
        site, _ = tenants.create_site(s, client, "Office")
        warehouse, _ = tenants.create_site(s, client, "Warehouse")
        a = Device(site_id=site.id, machine_guid=GUID_A, hostname="OFFICE-PC", token_hash="a" * 64, enrolled_at=site.created_at)
        b = Device(site_id=warehouse.id, machine_guid=GUID_B, hostname="office-pc.corp.local", token_hash="b" * 64,
                   enrolled_at=site.created_at)
        s.add_all([a, b])
        s.flush()

        def scan(*hosts):
            return sensor.store(s, site, sensor.Report.model_validate(_scan(*hosts)))

        # The printer answers on two addresses; Redis listens only on the second one.
        first = _host("10.0.0.5", PRINTER_MAC, ports=(80,))
        second = _host("10.0.0.6", PRINTER_MAC, ports=(6379,), issues=(REDIS,))
        named = _host("10.0.0.7", LAPTOP_MAC, name="OFFICE-PC")
        assert scan(first, second, named) == 2
        hosts = {h.key: h for h in s.scalars(select(NetworkHost))}
        assert sorted(p["port"] for p in hosts[f"mac:{PRINTER_MAC}"].ports) == [80, 6379]
        assert [(i.check_id, i.status) for i in s.scalars(select(NetworkIssue))] == [("PIS-0005", "open")]
        # Two PCs of this client are called OFFICE-PC: the name links the host to neither.
        assert hosts[f"mac:{LAPTOP_MAC}"].device_id is None

        # Next scan: the first address is clean, but the check could not finish on the second.
        unchecked = _host("10.0.0.6", PRINTER_MAC, ports=(6379,))
        unchecked["unchecked_ports"] = [6379]
        scan(_host("10.0.0.5", PRINTER_MAC, ports=(80,)), unchecked)
        s.expire_all()
        assert [i.status for i in s.scalars(select(NetworkIssue))] == ["open"]
        # Both addresses checked and clean: fixed.
        scan(_host("10.0.0.5", PRINTER_MAC, ports=(80,)), _host("10.0.0.6", PRINTER_MAC, ports=(6379,)))
        s.expire_all()
        assert [i.status for i in s.scalars(select(NetworkIssue))] == ["fixed"]

        # Once the warehouse PC is renamed, the name points at one PC again.
        b.hostname = "WAREHOUSE-PC"
        s.flush()
        scan(named)
        s.expire_all()
        assert s.scalars(select(NetworkHost).where(NetworkHost.mac == LAPTOP_MAC)).one().device_id == a.id


def test_real_agent_scan_and_notes(session):
    """A scan shaped exactly like agent 0.3.0's (lab VLAN): score-0 checks are notes, not issues."""
    rdp = {"id": "PIS-0010", "port": 3389, "title": "Remote Desktop (RDP) reachable", "cvss": 0.0, "evidence": "port open", "solution": None}
    ver = {"id": "PIS-0012", "port": 22, "title": "Software version detected", "cvss": 0.0, "evidence": "OpenSSH 10.0p2", "solution": None}
    redis = {"id": "PIS-0003", "port": 6379, "title": "Redis database accessible without authentication", "cvss": 9.3,
             "evidence": "INFO command answered without a password.", "solution": "Set requirepass."}
    body = _scan(
        {**_host("172.26.71.221", SENSOR_MAC, "W11-DEV01", ports=[22, 3389]), "issues": [rdp, ver], "rtt_ms": None,
         "vendor": "Proxmox Server Solutions GmbH"},
        {**_host("172.26.71.244", "02:97:e4:eb:35:ac", ports=[22, 6379]), "issues": [redis, ver], "vendor": "Private (randomized) address"},
    )
    body["hosts"][0]["ports"][0]["service"] = "unknown"
    with db.session_scope() as s:
        client = tenants.create_client(s, "Lab")
        site, _ = tenants.create_site(s, client, "Office")
        sensor.store(s, site, sensor.Report.model_validate(body))
        site_id = site.id
    from bearwatch.web import network_counts

    with db.session_scope() as s:
        assert network_counts(s, site_id=site_id)["net_issues"] == 1  # Redis only
    with TestClient(app) as c:
        _sign_in(c)
        page = c.get(f"/sites/{site_id}/network").text
        assert "Redis database accessible without authentication" in page
        assert "Remote Desktop (RDP) reachable" in page  # shown as a note on the host row
        assert "22 unknown" not in page


def test_severity_and_silence():
    assert [sensor.severity(x) for x in (9.3, 7.0, 5.1, 2.0, None, 0.0)] == ["critical", "high", "medium", "low", "medium", "info"]
    assert not sensor.is_issue(0.0) and sensor.is_issue(None) and sensor.is_issue(2.1)
    site = Site(sensor_device_id=None, sensor_scan_at=None)
    assert not sensor.sensor_silent(site, 240)
    site.sensor_device_id = 1
    assert not sensor.sensor_silent(site, 240)  # waiting for the first scan is not silence
    from bearwatch.intel.common import utcnow

    site.sensor_scan_at = utcnow() - timedelta(hours=8)
    assert not sensor.sensor_silent(site, 240)
    site.sensor_scan_at = utcnow() - timedelta(hours=10)
    assert sensor.sensor_silent(site, 240)
