"""Long-running worker for the Compose `worker` service.

Two loops on one timer:
- every 30 s, evaluate devices whose inventory changed (or whose findings need a refresh);
- every 5 min, run any feed sync whose last success is older than its interval, then queue
  every device for re-evaluation so new CVEs and KEV listings reach findings without waiting
  for the agent. A failing feed backs off so it never blocks the others.
"""

import logging
import time
from datetime import timedelta

from . import findings
from .db import init_db, session_scope
from .intel.common import run_sync, utcnow
from .jobs import JOBS
from .models import SyncState

log = logging.getLogger("bearwatch.worker")
DEVICE_TICK = 30
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
    while True:
        with session_scope() as s:
            if findings.evaluate_pending(s) == 0:
                return


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    init_db()
    log.info("worker started, jobs: %s", ", ".join(JOBS))
    last_feeds = 0.0
    while True:
        if time.monotonic() - last_feeds >= FEED_TICK or last_feeds == 0.0:
            run_feeds()
            last_feeds = time.monotonic()
        try:
            run_devices()
        except Exception:
            log.exception("device evaluation loop failed")
        time.sleep(DEVICE_TICK)


if __name__ == "__main__":
    main()
