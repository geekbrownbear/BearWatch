import threading
from datetime import timedelta

from bearwatch import findings, worker
from bearwatch.models import SyncState


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
