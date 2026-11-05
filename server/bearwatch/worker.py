"""Long-running worker for the Compose `worker` service.

Two loops on separate threads, so a long feed sync never holds up devices:
- devices (main thread), every 30 s: evaluate devices whose inventory changed (or whose
  findings need a refresh), rescore findings whose exception has ended, and queue every device
  again if the posture rules changed since the last deploy;
- feeds (background thread), every 5 min: run any feed sync whose last success is older than
  its interval, then queue every device for re-evaluation so new CVEs and KEV listings reach
  findings without waiting for the agent. A failing feed backs off so it never blocks the
  others.

The first NVD sync takes over an hour. Before the split, a PC enrolled during it showed no
findings, not even its posture ones, until the sync ended.
"""

import logging
import threading
import time
from datetime import timedelta

from . import external, findings, halo, posture, scoring
from .db import init_db, session_scope
from .intel.common import run_sync, utcnow
from .jobs import JOBS
from .models import SyncState

log = logging.getLogger("bearwatch.worker")
DEVICE_TICK = 30
HALO_TICK = 900  # HaloPSA tickets, after device evaluation (docs/halo.md)
EXTERNAL_TICK = 3600  # look for public addresses and domains due their weekly check (docs/external.md)
FEED_TICK = 300
ERROR_BACKOFF = timedelta(minutes=30)


def due_jobs() -> list[str]:
    now, due = utcnow(), []
    with session_scope() as s:
        for name, (_, every) in JOBS.items():
            st = s.get(SyncState, name)
            if st is None or st.last_success is None:
                # Never succeeded: run, unless it errored very recently.
                if st and st.last_status == "error" and st.last_started and now - st.last_started < ERROR_BACKOFF:
                    continue
                due.append(name)
            elif st.last_status == "error" and st.last_started and now - st.last_started < ERROR_BACKOFF:
                continue
            elif now - st.last_success >= every:
                due.append(name)
    return due


def run_feeds() -> None:
    synced = 0
    for name in due_jobs():
        try:
            run_sync(name, JOBS[name][0])
            synced += 1
        except Exception:  # logged in run_sync; keep going with other feeds
            pass
    if synced:
        with session_scope() as s:
            n = findings.mark_all_for_rematch(s)
        if n:
            log.info("intel updated; %d devices queued for re-evaluation", n)


def run_devices() -> None:
    with session_scope() as s:
        scoring.rescore_lapsed(s)  # exceptions that ended since the last tick
        n = posture.rematch_if_changed(s)  # a deploy changed the posture rules
        if n:
            log.info("posture rules changed; %d devices queued for re-evaluation", n)
    while True:
        with session_scope() as s:
            if findings.evaluate_pending(s) == 0:
                return


def run_halo() -> None:
    """Live ticket sync only. A dry run writes nothing; `bearwatch halo sync` shows what it would do."""
    api = halo.api_from_settings()
    if api is None or isinstance(api, halo.DryRunApi):
        return
    try:
        run_sync("halo", lambda s: halo.sync(s, api))
    except Exception:  # logged in run_sync
        pass


def feeds_loop(stop: threading.Event, tick: float = FEED_TICK) -> None:
    """Run due feed syncs now and then every `tick` seconds until `stop` is set."""
    while not stop.is_set():
        try:
            run_feeds()
        except Exception:
            log.exception("feed loop failed")
        stop.wait(tick)


def start_feeds(stop: threading.Event, tick: float = FEED_TICK) -> threading.Thread:
    t = threading.Thread(target=feeds_loop, args=(stop, tick), name="feeds", daemon=True)
    t.start()
    return t


def external_loop(stop: threading.Event, tick: float = EXTERNAL_TICK) -> None:
    """Weekly checks of public addresses and domains, on their own thread: each can wait on a
    slow lookup or TLS connection, and that must never hold up device evaluation."""
    while not stop.is_set():
        try:
            run_sync("external", external.run_due)
        except Exception:  # logged in run_sync
            pass
        stop.wait(tick)


def start_external(stop: threading.Event, tick: float = EXTERNAL_TICK) -> threading.Thread:
    t = threading.Thread(target=external_loop, args=(stop, tick), name="external", daemon=True)
    t.start()
    return t


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    init_db()
    log.info("worker started, jobs: %s", ", ".join(JOBS))
    feeds = start_feeds(threading.Event())
    ext = start_external(threading.Event())
    last_halo = 0.0
    while True:
        try:
            run_devices()
        except Exception:
            log.exception("device evaluation loop failed")
        if time.monotonic() - last_halo >= HALO_TICK:
            last_halo = time.monotonic()
            run_halo()
        if not ext.is_alive():
            log.error("external check thread stopped; restarting it")
            ext = start_external(threading.Event())
        if not feeds.is_alive():  # feeds_loop catches everything, so this should never happen
            log.error("feed thread stopped; restarting it")
            feeds = start_feeds(threading.Event())
        time.sleep(DEVICE_TICK)


if __name__ == "__main__":
    main()
