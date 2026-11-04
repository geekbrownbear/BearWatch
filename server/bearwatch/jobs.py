"""Registry of sync jobs and how often each should run."""

from collections.abc import Callable
from datetime import timedelta

from sqlalchemy.orm import Session

from .intel import epss, kev, msrc, nvd, winget


def _kev(s: Session) -> int:
    return kev.sync_cisa(s) + kev.sync_vulncheck(s)


JOBS: dict[str, tuple[Callable[[Session], int], timedelta]] = {
    "kev": (_kev, timedelta(hours=6)),
    "epss": (lambda s: epss.sync(s), timedelta(hours=24)),
    "nvd": (lambda s: nvd.sync(s), timedelta(hours=2)),
    "msrc": (lambda s: msrc.sync(s), timedelta(hours=24)),
    "winget": (lambda s: winget.sync(s), timedelta(hours=24)),
}
