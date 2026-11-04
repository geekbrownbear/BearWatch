"""Third-party application matching via NVD CPE rules.

A program from the Windows Uninstall registry (DisplayName, Publisher, DisplayVersion) is
resolved to CPE vendor/product pairs through intel/cpe_overrides.json first. If no rule
matches, a cautious fallback tries the normalized name as a CPE product and only accepts it
when exactly one vendor uses that product name. Anything else is reported as unresolved, so
it can be added to the overrides file rather than guessed at.
"""

import re
from dataclasses import dataclass, field

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..intel import overrides
from ..models import CpeMatch, WingetPackage
from ..versions import Version, in_range
from .enrich import CveContext, enrich, rank_key

# CPE target_sw values that mean "not this Windows install".
_OTHER_OS = {"macos", "mac_os", "mac_os_x", "linux", "android", "iphone_os", "ios", "ipados", "chrome_os"}


def normalize(name: str) -> str:
    n = name.lower()
    n = re.sub(r"\((x64|x86|64-bit|32-bit)[^)]*\)", " ", n)
    n = re.sub(r"\b\d+(\.\d+)+\b", " ", n)
    n = re.sub(r"[^a-z0-9+]+", "_", n).strip("_")
    return n


@dataclass
class AppResult:
    name: str
    version: str
    resolved_by: str  # override | heuristic | unresolved
    cpe: list[tuple[str, str]]
    winget_id: str | None = None
    latest_version: str | None = None
    outdated: bool | None = None
    cves: list[CveContext] = field(default_factory=list)


def _heuristic(session: Session, name: str) -> list[tuple[str, str]]:
    prod = normalize(name)
    if not prod:
        return []
    vendors = session.execute(
        select(CpeMatch.vendor).where(CpeMatch.part == "a", CpeMatch.product == prod).distinct().limit(3)
    ).scalars().all()
    return [(vendors[0], prod)] if len(vendors) == 1 else []


def _winget(session: Session, rule_id: str | None, name: str) -> WingetPackage | None:
    if rule_id:
        pkg = session.get(WingetPackage, rule_id)
        if pkg:
            return pkg
    # Fall back to an exact (case-insensitive) package name match; ambiguous means none.
    hits = session.scalars(select(WingetPackage).where(func.lower(WingetPackage.name) == name.lower().strip()).limit(2)).all()
    return hits[0] if len(hits) == 1 else None


def _unbounded(r: CpeMatch) -> bool:
    """A '*' rule with no version bounds claims every version ever released.

    NVD writes these mostly for old protocol-level CVEs (e.g. Logjam lists every browser), so
    counting them would flag fully current software. Off by default, see include_unbounded.
    """
    return r.version in ("*", "-") and not (
        r.version_start_incl or r.version_start_excl or r.version_end_incl or r.version_end_excl
    )


def match(session: Session, name: str, version: str, publisher: str | None = None, include_unbounded: bool = False) -> AppResult:
    rule = overrides.resolve(name, publisher)
    if rule:
        pairs, how = list(rule.cpe), "override"
    else:
        pairs = _heuristic(session, name)
        how = "heuristic" if pairs else "unresolved"

    result = AppResult(name=name, version=version, resolved_by=how, cpe=pairs)
    pkg = _winget(session, rule.winget if rule else None, name)
    if pkg:
        result.winget_id, result.latest_version = pkg.id, pkg.latest_version
        if pkg.latest_version:
            result.outdated = Version(version) < Version(pkg.latest_version)

    if not pairs:
        return result
    cond = or_(*[(CpeMatch.vendor == v) & (CpeMatch.product == p) for v, p in pairs])
    rows = session.scalars(select(CpeMatch).where(CpeMatch.part == "a", cond)).all()
    hit: set[str] = set()
    for r in rows:
        if r.target_sw.lower() in _OTHER_OS:
            continue
        if r.platforms and not any("windows" in p for p in r.platforms):
            continue  # needs a non-Windows platform (e.g. Chrome on macOS)
        if not include_unbounded and _unbounded(r):
            continue
        if in_range(
            version,
            exact=r.version,
            start_incl=r.version_start_incl,
            start_excl=r.version_start_excl,
            end_incl=r.version_end_incl,
            end_excl=r.version_end_excl,
        ):
            hit.add(r.cve_id)
    result.cves = sorted(enrich(session, list(hit)).values(), key=rank_key)
    return result
