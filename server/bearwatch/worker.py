"""Long-running sync worker for the Compose `worker` service.

Wakes every few minutes, runs any job whose last success is older than its interval, and
backs off a failing job so one broken feed never blocks the others.
"""

import logging
import time
from datetime import timedelta

from .db import init_db, session_scope
from .intel.common import run_sync, utcnow
from .jobs import JOBS
from .models import SyncState

log = logging.getLogger("bearwatch.worker")
TICK = 300
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


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    init_db()
    log.info("worker started, jobs: %s", ", ".join(JOBS))
    while True:
        for name in due_jobs():
            try:
                run_sync(name, JOBS[name][0])
            except Exception:  # logged in run_sync; keep going with other feeds
                pass
        time.sleep(TICK)


if __name__ == "__main__":
    main()
