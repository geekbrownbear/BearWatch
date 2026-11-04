from bearwatch.db import upsert
from bearwatch.intel import msrc
from bearwatch.match import apps, windows
from bearwatch.models import CpeMatch, Epss, Kev, MsrcFix, MsrcProduct, WingetPackage

WIN11 = "Windows 11 Version 23H2 for x64-based Systems"


def _seed_windows(s):
    s.add(MsrcProduct(product_id="12242", name=WIN11))
    s.add(MsrcProduct(product_id="99999", name=f"Some Add-on on {WIN11}"))
    # September CU (fixed build) and October CU, which supersedes September.
    s.add(MsrcFix(doc_id="2026-Sep", cve_id="CVE-2026-0001", product_id="12242", kb="5040001", fixed_build="10.0.22631.4100", supersedes=["5030001"]))
    s.add(MsrcFix(doc_id="2026-Oct", cve_id="CVE-2026-0002", product_id="12242", kb="5050001", fixed_build="10.0.22631.4300", supersedes=["5040001"]))
    # A standalone update with no fixed build: only the KB path can prove it.
    s.add(MsrcFix(doc_id="2026-Oct", cve_id="CVE-2026-0003", product_id="12242", kb="5050002", fixed_build=None, supersedes=[]))
    # Unverifiable row ("Release Notes"), must not show as open.
    s.add(MsrcFix(doc_id="2026-Oct", cve_id="CVE-2026-0004", product_id="12242", kb="Release Notes", fixed_build=None, supersedes=[]))
    s.add(Kev(cve_id="CVE-2026-0002", source="cisa"))
    s.flush()


def test_product_name():
    assert windows.product_name("10.0.22631.4317") == WIN11
    assert windows.product_name("10.0.20348.2000", server=True) == "Windows Server 2022"
    assert windows.product_name("10.0.99999.1") is None


def test_windows_by_build(session):
    _seed_windows(session)
    r = windows.match(session, WIN11, "10.0.22631.4200", [])
    open_ids = [o.cve_id for o in r.open]
    # 0001 fixed by build; 0002 open and ranked first (KEV); 0003 open (KB missing); 0004 ignored
    assert open_ids == ["CVE-2026-0002", "CVE-2026-0003"]
    assert r.fixed_count == 1
    assert r.open[0].context.exploit_tier == 1
    # October CU closes its own CVE; the standalone KB closes the other.
    assert r.by_fix[0]["kb"] in {"5050001", "5050002"} and r.by_fix[0]["closes"] == 1
    assert {g["kb"]: g["closes"] for g in r.by_fix} == {"5050001": 1, "5050002": 1}
    assert r.product_ids == ["12242"]  # add-on product not pulled in


def test_windows_sibling_build_family(session):
    _seed_windows(session)
    # MSRC lists the 22H2 build (22621) as the fixed build on the 23H2 product.
    session.add(MsrcFix(doc_id="2025-Sep", cve_id="CVE-2025-0005", product_id="12242", kb="5062552", fixed_build="10.0.22621.5624", supersedes=[]))
    session.flush()
    r = windows.match(session, WIN11, "10.0.22631.5700", [])
    assert "CVE-2025-0005" not in [o.cve_id for o in r.open]
    r = windows.match(session, WIN11, "10.0.22631.5600", [])
    assert "CVE-2025-0005" in [o.cve_id for o in r.open]


def test_windows_by_kb_and_supersedence(session):
    _seed_windows(session)
    # Unknown/odd build string forces the KB path; the October CU supersedes September's.
    r = windows.match(session, WIN11, "10.0.22631", ["KB5050001", "kb5050002"])
    assert [o.cve_id for o in r.open] == []
    assert r.fixed_count == 3


def test_msrc_store_replaces_month(session):
    from tests.test_parsers import MSRC_DOC

    assert msrc.store_document(session, "2026-Oct", MSRC_DOC) == 1
    assert msrc.store_document(session, "2026-Oct", MSRC_DOC) == 1
    assert session.query(MsrcFix).count() == 1


def test_app_match(session):
    upsert(
        session,
        WingetPackage,
        [{"id": "Google.Chrome", "name": "Google Chrome", "latest_version": "131.0.6778.86", "norm_names": [], "norm_publishers": [], "product_codes": []}],
        key=("id",),
    )
    base = {"criteria": "x", "part": "a", "vendor": "google", "product": "chrome", "version": "*", "target_sw": "*", "version_start_incl": None, "version_start_excl": None, "version_end_incl": None}
    session.add(CpeMatch(cve_id="CVE-2023-7024", version_end_excl="120.0.6099.129", **base))
    session.add(CpeMatch(cve_id="CVE-2020-0001", version_end_excl="80.0", **base))
    session.add(CpeMatch(cve_id="CVE-2023-9999", version_end_excl="121.0", **{**base, "target_sw": "android"}))
    # Chrome AND macOS: not applicable to a Windows install.
    session.add(CpeMatch(cve_id="CVE-2025-14174", version_end_excl="143.0", platforms=["apple:macos"], **base))
    # Chrome on Windows/Linux/macOS: applies.
    session.add(CpeMatch(cve_id="CVE-2024-7971", version_end_excl="128.0", platforms=["apple:macos", "microsoft:windows"], **base))
    # Unbounded '*' (Logjam style): ignored unless asked for.
    session.add(CpeMatch(cve_id="CVE-2015-4000", version_end_excl=None, **base))
    session.add(Epss(cve_id="CVE-2023-7024", score=0.5, percentile=0.99, score_date=None))
    session.flush()

    r = apps.match(session, "Google Chrome", "120.0.6099.71", "Google LLC")
    assert r.resolved_by == "override"
    assert sorted(c.cve_id for c in r.cves) == ["CVE-2023-7024", "CVE-2024-7971"]
    assert r.winget_id == "Google.Chrome" and r.outdated is True
    r = apps.match(session, "Google Chrome", "120.0.6099.71", include_unbounded=True)
    assert "CVE-2015-4000" in [c.cve_id for c in r.cves]

    r = apps.match(session, "Some Unknown Tool", "1.0")
    assert r.resolved_by == "unresolved" and r.cves == []


def test_app_heuristic(session):
    session.add(CpeMatch(cve_id="CVE-2024-1111", criteria="x", part="a", vendor="acme", product="widgetpro", version="2.0", target_sw="*"))
    session.flush()
    r = apps.match(session, "WidgetPro 2.0 (x64)", "2.0")
    assert r.resolved_by == "heuristic" and r.cpe == [("acme", "widgetpro")]
    assert [c.cve_id for c in r.cves] == ["CVE-2024-1111"]


def test_overrides_file_loads():
    from bearwatch.intel import overrides

    rule = overrides.resolve("Mozilla Firefox ESR (x64 en-US)")
    assert rule and rule.cpe == (("mozilla", "firefox_esr"),)
    assert overrides.resolve("Mozilla Firefox (x64 en-US)").cpe == (("mozilla", "firefox"),)
    assert overrides.resolve("Notepad++ (64-bit x64)").cpe == (("notepad-plus-plus", "notepad\\+\\+"),)
