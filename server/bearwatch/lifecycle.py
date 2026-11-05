"""Is this PC's Windows version still getting security updates? Data: intel/windows_lifecycle.toml."""

import tomllib
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

from .config import get_settings
from .posture import build_number

SOON_DAYS = 90  # "ends soon" window for the report and device page


@dataclass(frozen=True)
class Support:
    name: str  # "Windows 11, version 24H2"
    ends: date | None  # None: unknown
    status: str  # supported | ending | ended | unknown

    @property
    def label(self) -> str:
        when = f"{self.ends:%b} {self.ends.day}, {self.ends.year}" if self.ends else ""
        if self.status == "ended":
            return f"Out of support since {when}" if self.ends else "Out of support"
        if self.status == "ending":
            return f"Support ends {when}"
        if self.status == "supported":
            return f"Supported until {when}"
        return "Support date unknown"


@lru_cache
def _table(path: str | None = None) -> dict:
    p = Path(path) if path else get_settings().lifecycle_path
    return tomllib.loads(p.read_text(encoding="utf-8"))


def support(os_build: str | None, caption: str | None, is_server: bool, today: date | None = None) -> Support:
    today = today or date.today()
    build = build_number(os_build)
    cap = (caption or "").lower()
    if build is None:
        return Support("Unknown Windows version", None, "unknown")
    # Long-term servicing editions have their own, much longer dates; don't guess.
    if "ltsc" in cap or "ltsb" in cap:
        return Support(caption or f"Build {build}", None, "unknown")
    t = _table()
    if is_server:
        row = next((r for r in t.get("server", []) if r["build"] == build), None)
        ends = row["ends"] if row else None
    else:
        row = next((r for r in t.get("client", []) if r["build"] == build), None)
        if row is None:
            # An unlisted Windows 10 release stopped getting updates no later than the next
            # listed Windows 10 release did (Windows 11 starts at build 22000).
            later = [r for r in t.get("client", []) if build < r["build"] < 22000]
            bound = min((r["home_pro"] for r in later), default=None) if 10000 <= build < 22000 else None
            if bound is not None and bound <= today:
                return Support(f"Windows 10 (build {build})", None, "ended")
            ends = None
        else:
            enterprise = any(w in cap for w in ("enterprise", "education"))
            ends = row["enterprise"] if enterprise else row["home_pro"]
    if row is None or ends is None:
        return Support(f"Build {build}", None, "unknown")
    if ends <= today:
        status = "ended"
    elif (ends - today).days <= SOON_DAYS:
        status = "ending"
    else:
        status = "supported"
    return Support(row["name"], ends, status)
