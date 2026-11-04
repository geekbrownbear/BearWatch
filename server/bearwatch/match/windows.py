"""Windows OS patch-gap matching from MSRC data.

Input: the MSRC product (e.g. "Windows 11 Version 23H2 for x64-based Systems"), the device's
full build (10.0.22631.4317) and installed KBs. A CVE is open when none of its fixes for that
product is satisfied, where a fix is satisfied if:

1. MSRC gives a FixedBuild on the same base build and the device's revision (UBR) is >= it, or
2. its KB is installed, or an installed KB supersedes it (transitively).

Build comparison handles cumulative updates; the KB path covers older products and the
standalone updates (e.g. SSUs, .NET) that do not carry a fixed build.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import MsrcFix, MsrcProduct, MsrcVuln
from ..versions import Version
from .enrich import CveContext, enrich, rank_key

# Base build -> MSRC product name stem. Client and server share some builds.
CLIENT_BUILDS = {
    26200: "Windows 11 Version 25H2",
    26100: "Windows 11 Version 24H2",
    22631: "Windows 11 Version 23H2",
    22621: "Windows 11 Version 22H2",
    19045: "Windows 10 Version 22H2",
    19044: "Windows 10 Version 21H2",
    17763: "Windows 10 Version 1809",
    14393: "Windows 10 Version 1607",
}
SERVER_BUILDS = {
    26100: "Windows Server 2025",
    20348: "Windows Server 2022",
    17763: "Windows Server 2019",
    14393: "Windows Server 2016",
}
_ARCH = {"x64": "x64-based Systems", "arm64": "ARM64-based Systems", "x86": "32-bit Systems"}


def product_name(build: str, arch: str = "x64", server: bool = False, core: bool = False) -> str | None:
    """MSRC product name for a Windows build, or None if we do not know the build."""
    parts = build.split(".")
    base = int(parts[2]) if len(parts) >= 3 else int(parts[0])
    if server:
        stem = SERVER_BUILDS.get(base)
        if not stem:
            return None
        return f"{stem} (Server Core installation)" if core else stem
    stem = CLIENT_BUILDS.get(base)
    if not stem:
        return None
    return f"{stem} for {_ARCH.get(arch, _ARCH['x64'])}"


def _norm_kb(kb: str) -> str:
    m = re.search(r"(\d{6,8})", kb)
    return m.group(1) if m else kb.strip().upper()


def _covered_kbs(installed: set[str], supersedes: dict[str, set[str]]) -> set[str]:
    """All KBs whose fixes are present: installed ones plus everything they supersede, transitively."""
    covered, stack = set(), list(installed)
    while stack:
        kb = stack.pop()
        if kb in covered:
            continue
        covered.add(kb)
        stack.extend(supersedes.get(kb, ()))
    return covered


# Versions delivered as an enablement package on top of an older one share the same cumulative
# update and revision (UBR) numbering, and MSRC sometimes lists the sibling's build as the fixed
# build. Each base build maps to its family root.
_FAMILY = {22631: 22621, 19045: 19044, 26200: 26100}


def _family(base: int) -> int:
    return _FAMILY.get(base, base)


def _build_satisfies(device_build: str, fixed_build: str) -> bool | None:
    """True/False when comparable (same major.minor and build family), None when not."""
    d, f = device_build.split("."), fixed_build.split(".")
    if len(d) < 4 or len(f) < 4 or d[:2] != f[:2]:
        return None
    try:
        if _family(int(d[2])) != _family(int(f[2])):
            return None
        return int(d[3]) >= int(f[3])
    except ValueError:
        return None


@dataclass
class OpenCve:
    cve_id: str
    title: str | None
    severity: str | None
    fixes: list[dict]
    context: CveContext


@dataclass
class WindowsResult:
    product: str
    product_ids: list[str]
    build: str
    installed_kbs: list[str]
    open: list[OpenCve] = field(default_factory=list)
    fixed_count: int = 0
    # Group-by-fix view: newest KB that closes the most, with the CVEs it closes.
    by_fix: list[dict] = field(default_factory=list)


def find_products(session: Session, name: str) -> list[MsrcProduct]:
    exact = session.scalars(select(MsrcProduct).where(MsrcProduct.name == name)).all()
    if exact:
        return list(exact)
    return list(session.scalars(select(MsrcProduct).where(MsrcProduct.name.ilike(f"%{name}%"))).all())


def match(session: Session, product: str, build: str, installed_kbs: list[str]) -> WindowsResult:
    products = find_products(session, product)
    if not products:
        raise LookupError(f"no MSRC product matches {product!r}; run `bearwatch sync msrc` or check the name")
    # Prefer the exact name; a substring hit can pull in add-on products ("... on Windows 11").
    exact = [p for p in products if p.name == product]
    chosen = exact or [p for p in products if " on " not in p.name] or products
    pids = [p.product_id for p in chosen]

    fixes = session.scalars(select(MsrcFix).where(MsrcFix.product_id.in_(pids))).all()

    # Supersedence edges come from every fix we know about, not just this product's.
    supersedes: dict[str, set[str]] = defaultdict(set)
    for kb, sup in session.execute(select(MsrcFix.kb, MsrcFix.supersedes)):
        if kb and sup:
            supersedes[kb].update(sup)

    installed = {_norm_kb(k) for k in installed_kbs if k.strip()}
    covered = _covered_kbs(installed, supersedes)

    per_cve: dict[str, list[MsrcFix]] = defaultdict(list)
    for f in fixes:
        per_cve[f.cve_id].append(f)

    open_ids: dict[str, list[MsrcFix]] = {}
    fixed = 0
    for cve, all_fixes in per_cve.items():
        # A fix we can verify needs a fixed build or a numeric KB; "Release Notes" style rows can't be checked.
        cve_fixes = [f for f in all_fixes if f.fixed_build or (f.kb and f.kb.isdigit())]
        if not cve_fixes:
            continue
        if _satisfied(cve_fixes, build, covered):
            fixed += 1
        else:
            open_ids[cve] = cve_fixes

    ctx = enrich(session, list(open_ids))
    titles = {v.cve_id: v.title for v in session.scalars(select(MsrcVuln).where(MsrcVuln.cve_id.in_(list(open_ids) or [""])))}
    result = WindowsResult(product=chosen[0].name, product_ids=pids, build=build, installed_kbs=sorted(installed), fixed_count=fixed)
    for cve, cve_fixes in open_ids.items():
        sev = next((f.severity for f in cve_fixes if f.severity), None)
        if ctx[cve].cvss is None:
            # MSRC carries its own CVSS base score; use it until (or if) NVD has one.
            ctx[cve].cvss = next((f.cvss_score for f in cve_fixes if f.cvss_score), None)
        result.open.append(
            OpenCve(
                cve_id=cve,
                title=titles.get(cve),
                severity=sev,
                fixes=[{"kb": f.kb, "fixed_build": f.fixed_build, "subtype": f.subtype, "url": f.url} for f in cve_fixes],
                context=ctx[cve],
            )
        )
    result.open.sort(key=lambda o: rank_key(o.context))

    # Group by fix. Each group lists the CVEs that name this KB directly ("cves") and, because
    # cumulative updates supersede older ones, every open CVE installing it would close
    # ("closes"). Ordered by how much each fix closes, newest build first on ties.
    groups: dict[str, dict] = {}
    for o in result.open:
        for f in o.fixes:
            key = f["kb"] or "unknown"
            g = groups.setdefault(key, {"kb": key, "fixed_build": f["fixed_build"], "cves": set()})
            g["cves"].add(o.cve_id)
    for g in groups.values():
        kb_cover = _covered_kbs(installed | {g["kb"]}, supersedes)
        # Installing a cumulative update moves the device to its build revision.
        same_family = g["fixed_build"] and _build_satisfies(build, g["fixed_build"]) is not None
        after = g["fixed_build"] if same_family else build
        g["closed"] = sorted(cve for cve in open_ids if _satisfied(open_ids[cve], after, kb_cover))
        g["closes"] = len(g["closed"])
    ordered = sorted(groups.values(), key=lambda g: (g["closes"], Version(g["fixed_build"] or "0")), reverse=True)
    result.by_fix = [{**g, "cves": sorted(g["cves"])} for g in ordered]
    return result


def _satisfied(cve_fixes: list[MsrcFix], build: str, covered: set[str]) -> bool:
    for f in cve_fixes:
        by_build = _build_satisfies(build, f.fixed_build) if f.fixed_build else None
        if by_build is True or (by_build is None and f.kb and f.kb in covered):
            return True
    return False
