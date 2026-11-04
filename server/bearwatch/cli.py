"""Command line: `bearwatch <command>`.

  bearwatch initdb
  bearwatch sync [kev|epss|nvd|msrc|winget|all]
  bearwatch status
  bearwatch windows --build 10.0.22631.4317 [--kb KB5044285 ...] [--server] [--product NAME]
  bearwatch app --name "Google Chrome" --version 120.0.6099.71 [--publisher Google]
  bearwatch ssvc CVE-2024-3400 [...]
  bearwatch overrides check
"""

import argparse
import json
import logging
import sys

from sqlalchemy import select

from .db import init_db, session_scope
from .intel import overrides, vulnrichment
from .intel.common import run_sync
from .jobs import JOBS
from .match import apps, windows
from .models import CpeMatch, SyncState


def _ctx_line(c) -> str:
    kev = ",".join(c.kev) or "-"
    epss = f"{c.epss:.3f}" if c.epss is not None else "-"
    cvss = f"{c.cvss:.1f}" if c.cvss is not None else "-"
    return f"tier {c.exploit_tier}  cvss {cvss:>4}  epss {epss:>5}  kev {kev:<14}"


def cmd_sync(args) -> int:
    names = list(JOBS) if args.source == "all" else [args.source]
    rc = 0
    for n in names:
        try:
            run_sync(n, JOBS[n][0])
        except Exception as e:
            print(f"{n}: FAILED {e}", file=sys.stderr)
            rc = 1
    return rc


def cmd_status(_args) -> int:
    with session_scope() as s:
        rows = s.scalars(select(SyncState).order_by(SyncState.source)).all()
        if not rows:
            print("no syncs yet")
        for r in rows:
            print(f"{r.source:<8} {r.last_status or '-':<8} last ok {r.last_success or '-'}  rows {r.rows or 0}  {r.last_error or ''}")
    return 0


def cmd_windows(args) -> int:
    product = args.product or windows.product_name(args.build, args.arch, args.server, args.core)
    if not product:
        print(f"unknown build {args.build}; pass --product with the MSRC product name", file=sys.stderr)
        return 2
    with session_scope() as s:
        res = windows.match(s, product, args.build, args.kb or [])
    if args.json:
        print(json.dumps({**res.__dict__, "open": [{**o.__dict__, "context": o.context.as_dict()} for o in res.open]}, default=str, indent=1))
        return 0
    print(f"{res.product}  build {res.build}  KBs {', '.join(res.installed_kbs) or 'none'}")
    print(f"open CVEs: {len(res.open)}   fixed: {res.fixed_count}")
    if res.by_fix:
        top = res.by_fix[0]
        print(f"install KB{top['kb']} (build {top['fixed_build'] or '?'}) to close {top['closes']} of them")
        rest = len(res.open) - top["closes"]
        if rest > 0:
            others = ", ".join(f"KB{g['kb']}" for g in res.by_fix[1:4])
            print(f"  {rest} more need other updates: {others}{' ...' if len(res.by_fix) > 4 else ''}")
    for o in res.open[: args.limit]:
        print(f"  {o.cve_id:<16} {_ctx_line(o.context)} {o.severity or '':<10} {(o.title or '')[:60]}")
    return 0


def cmd_app(args) -> int:
    with session_scope() as s:
        res = apps.match(s, args.name, args.version, args.publisher)
    if args.json:
        print(json.dumps({**res.__dict__, "cves": [c.as_dict() for c in res.cves]}, default=str, indent=1))
        return 0
    cpe = ", ".join(f"{v}:{p}" for v, p in res.cpe) or "-"
    print(f"{res.name} {res.version}  resolved by {res.resolved_by} -> {cpe}")
    if res.winget_id:
        state = "outdated" if res.outdated else "current"
        print(f"winget {res.winget_id} latest {res.latest_version} ({state})  fix: winget upgrade --id {res.winget_id} -e")
    print(f"CVEs: {len(res.cves)}")
    for c in res.cves[: args.limit]:
        print(f"  {c.cve_id:<16} {_ctx_line(c)} {(c.description or '')[:60]}")
    return 0


def cmd_ssvc(args) -> int:
    with session_scope() as s:
        n = vulnrichment.enrich(s, args.cve)
    print(f"fetched {n}")
    return 0


def cmd_overrides_check(_args) -> int:
    missing = 0
    with session_scope() as s:
        for rule in overrides.rules():
            for v, p in rule.cpe:
                n = s.scalar(select(CpeMatch.id).where(CpeMatch.vendor == v, CpeMatch.product == p).limit(1))
                if n is None:
                    missing += 1
                    print(f"no NVD data: {v}:{p}   (rule {rule.name.pattern})")
    print("all rules have NVD data" if not missing else f"{missing} vendor/product pairs without NVD data")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(prog="bearwatch")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("initdb")
    p = sub.add_parser("sync")
    p.add_argument("source", choices=[*JOBS, "all"])
    sub.add_parser("status")

    p = sub.add_parser("windows", help="open Windows CVEs for a build + installed KBs")
    p.add_argument("--build", required=True, help="full build, e.g. 10.0.22631.4317")
    p.add_argument("--kb", action="append", help="installed KB (repeatable)")
    p.add_argument("--arch", default="x64", choices=["x64", "arm64", "x86"])
    p.add_argument("--server", action="store_true")
    p.add_argument("--core", action="store_true", help="Server Core installation")
    p.add_argument("--product", help="MSRC product name (overrides the build lookup)")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("app", help="CVEs for an installed application")
    p.add_argument("--name", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--publisher")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("ssvc", help="fetch CISA SSVC for CVEs")
    p.add_argument("cve", nargs="+")

    p = sub.add_parser("overrides")
    p.add_argument("action", choices=["check"])

    args = ap.parse_args(argv)
    init_db()
    handlers = {
        "initdb": lambda a: 0,
        "sync": cmd_sync,
        "status": cmd_status,
        "windows": cmd_windows,
        "app": cmd_app,
        "ssvc": cmd_ssvc,
        "overrides": cmd_overrides_check,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
