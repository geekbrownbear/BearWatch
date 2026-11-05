import threading
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from bearwatch import findings, worker
from bearwatch.api import app
from bearwatch.models import Device, SyncState

from .test_agent import _inventory, _post_inv, _seed


def test_devices_are_evaluated_while_a_feed_is_still_syncing(session, monkeypatch):
    """The first NVD sync takes over an hour; devices must not wait for it."""
    started, release = threading.Event(), threading.Event()

    def slow_feed(s):
        started.set()
        assert release.wait(10), "test never released the feed"
        return 7

    monkeypatch.setattr(worker, "JOBS", {"slow": (slow_feed, timedelta(hours=1))})
    evaluated = []
    monkeypatch.setattr(findings, "evaluate_pending", lambda s: evaluated.append(1) or 0)

    stop = threading.Event()
    t = worker.start_feeds(stop, tick=0.05)
    try:
        assert started.wait(5), "feed thread never started the sync"
        # The sync is still running. A device pass must finish anyway.
        done = threading.Event()
        threading.Thread(target=lambda: (worker.run_devices(), done.set()), daemon=True).start()
        assert done.wait(5), "device evaluation waited for the feed sync"
        assert evaluated
    finally:
        release.set()
        stop.set()
        t.join(5)
    assert not t.is_alive()
    session.expire_all()
    st = session.get(SyncState, "slow")
    assert st.last_status == "ok" and st.rows == 7


def test_devices_are_evaluated_while_halo_hangs(session, monkeypatch):
    """A Halo outage (30 s per timed-out call, one call per ticket) must not stall evaluation."""
    started, release = threading.Event(), threading.Event()

    def hung_halo():
        started.set()
        assert release.wait(10), "test never released Halo"

    monkeypatch.setattr(worker, "run_halo", hung_halo)
    evaluated = []
    monkeypatch.setattr(findings, "evaluate_pending", lambda s: evaluated.append(1) or 0)
    stop = threading.Event()
    t = worker.start_halo(stop, tick=0.05)
    try:
        assert started.wait(5), "halo thread never started"
        done = threading.Event()
        threading.Thread(target=lambda: (worker.run_devices(), done.set()), daemon=True).start()
        assert done.wait(5), "device evaluation waited for Halo"
        assert evaluated
    finally:
        release.set()
        stop.set()
        t.join(5)
    assert not t.is_alive()


def test_feed_loop_survives_errors(session, monkeypatch):
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("feed broke")

    monkeypatch.setattr(worker, "run_feeds", boom)
    stop = threading.Event()
    t = worker.start_feeds(stop, tick=0.01)
    try:
        for _ in range(500):
            if len(calls) >= 3:
                break
            threading.Event().wait(0.01)
    finally:
        stop.set()
        t.join(5)
    assert len(calls) >= 3, "the loop stopped after the first error"


def test_rematch_request_during_evaluation_is_kept(session, monkeypatch):
    """A feed that finishes mid-evaluation must leave the device queued for another pass."""
    key = _seed()
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"enroll_key": key, "machine_guid": "0f8fad5b-d9cb-469f-a165-70867728950e",
                                              "hostname": "BEAR-PC01", "agent_version": "0.1.0"})
        assert _post_inv(c, r.json()["token"], _inventory("10.0.22631.4317", "131.0.6778.86", "inv-0001")).status_code == 202

    real = findings._app_findings

    def feed_lands_midway(s, dev):
        findings.mark_all_for_rematch(s)  # what the feed thread does when its sync commits
        return real(s, dev)

    monkeypatch.setattr(findings, "_app_findings", feed_lands_midway)
    dev = session.scalars(select(Device)).one()
    findings.evaluate(session, dev)
    session.commit()
    session.expire_all()
    assert session.scalars(select(Device)).one().needs_match is True


def test_external_checks_run_on_their_own_thread(session, monkeypatch):
    """A slow external lookup must not hold up device evaluation."""
    from bearwatch import external

    started, release = threading.Event(), threading.Event()

    def slow(s):
        started.set()
        assert release.wait(10)
        return 0

    monkeypatch.setattr(external, "run_due", slow)
    stop = threading.Event()
    t = worker.start_external(stop, tick=0.05)
    try:
        assert started.wait(5)
        done = threading.Event()
        threading.Thread(target=lambda: (worker.run_devices(), done.set()), daemon=True).start()
        assert done.wait(5), "device evaluation waited for an external check"
    finally:
        release.set()
        stop.set()
        t.join(5)
