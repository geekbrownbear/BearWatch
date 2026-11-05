"""Command line: `bearwatch <command>`.

  bearwatch initdb
  bearwatch sync [kev|epss|nvd|msrc|winget|all]
  bearwatch status
  bearwatch windows --build 10.0.22631.4317 [--kb KB5044285 ...] [--server] [--product NAME]
  bearwatch app --name "Google Chrome" --version 120.0.6099.71 [--publisher Google]
  bearwatch ssvc CVE-2024-3400 [...]
  bearwatch overrides check
  bearwatch client list | add NAME
  bearwatch site add --client NAME --name SITE [--wua]   (prints the enrollment key once)
  bearwatch site rotate-key SITE_ID
  bearwatch evaluate [--all]
"""

import argparse
import json
import logging
import sys

from sqlalchemy import func, select

from . import findings, tenants
from .db import init_db, session_scope
from .intel import overrides, vulnrichment
from .intel.common import run_sync
from .jobs import JOBS
from .match import apps, windows
from .models import Client, CpeMatch, Device, Site, SyncState


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


def cmd_client(args) -> int:
    with session_scope() as s:
        if args.action == "add":
            c = tenants.create_client(s, args.name)
            print(f"client {c.id}: {c.name}")
        else:
            for c in s.scalars(select(Client).order_by(Client.name)):
                sites = s.scalars(select(Site).where(Site.client_id == c.id).order_by(Site.name)).all()
                print(f"{c.id:>4}  {c.name}")
                for site in sites:
                    n = s.scalar(select(func.count()).select_from(Device).where(Device.site_id == site.id))
                    print(f"        site {site.id}: {site.name}  key {site.enroll_key_hint}...  devices {n}  wua_check {site.wua_check}")
    return 0


def cmd_site(args) -> int:
    with session_scope() as s:
        if args.action == "add":
            client = s.scalar(select(Client).where(Client.name == args.client))
            if client is None:
                print(f"no client named {args.client!r}; add it with `bearwatch client add`", file=sys.stderr)
                return 2
            site, key = tenants.create_site(s, client, args.name, wua_check=args.wua)
        elif args.action == "sensor":
            site = s.get(Site, args.site_id)
            if site is None:
                print(f"no site {args.site_id}", file=sys.stderr)
                return 2
            dev = None
            if args.device != "none":
                dev = s.get(Device, int(args.device)) if args.device.isdigit() else None
                if dev is None:
                    print(f"no device {args.device}", file=sys.stderr)
                    return 2
            try:
                tenants.set_sensor(s, site, dev)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            print(f"site {site.id}: sensor {'off' if dev is None else f'{dev.hostname} (device {dev.id})'}")
            return 0
        else:
            site = s.get(Site, args.site_id)
            if site is None:
                print(f"no site {args.site_id}", file=sys.stderr)
                return 2
            key = tenants.rotate_site_key(s, site)
        print(f"site {site.id}: {site.name}")
        print(f"enrollment key (shown once): {key}")
    return 0


def cmd_report(args) -> int:
    from datetime import datetime as _dt

    from . import report

    month = _dt.strptime(args.month, "%Y-%m").date() if args.month else report.previous_month()
    with session_scope() as s:
        r = report.build(s, args.client_id, month)
        if args.html:
            data = report.render_html(r).encode()
        else:
            if not report.pdf_available():
                print("WeasyPrint is not installed; use --html", file=sys.stderr)
                return 2
            data = report.render_pdf(r)
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"{r.client.name} {r.month:%Y-%m}: grade {r.grade} ({r.score}), wrote {args.out}")
    return 0


def cmd_halo(args) -> int:
    from . import halo

    if args.action == "client":
        with session_scope() as s:
            c = s.get(Client, args.client_id)
            if c is None:
                print(f"no client {args.client_id}", file=sys.stderr)
                return 2
            c.halo_client_id = None if args.halo_id == "none" else int(args.halo_id)
            print(f"{c.name}: Halo client id {c.halo_client_id}")
        return 0
    api = halo.api_from_settings()
    if api is None:
        print("Halo is not set up: set BEARWATCH_HALO_URL, BEARWATCH_HALO_CLIENT_ID and BEARWATCH_HALO_CLIENT_SECRET", file=sys.stderr)
        return 2
    dry = isinstance(api, halo.DryRunApi)
    with session_scope() as s:
        n = halo.sync(s, api)
        if dry:
            s.rollback()  # session_scope then commits an empty transaction
    if dry:
        print("Dry run (BEARWATCH_HALO_DRY_RUN is on): nothing was sent or saved.")
        for call in api.calls:
            print("  would", *call)
        if not api.calls:
            print("  nothing to do")
    else:
        print(f"{n} tickets created, updated or closed")
    return 0


def cmd_external(args) -> int:
    from . import external
    from .intel.common import utcnow
    from .models import ExternalIssue, ExternalTarget

    with session_scope() as s:
        if args.action == "add":
            c = s.get(Client, args.client_id)
            if c is None:
                print(f"no client {args.client_id}", file=sys.stderr)
                return 2
            try:
                kind, value = external.normalize(args.value)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            s.add(ExternalTarget(client_id=c.id, kind=kind, value=value, created_at=utcnow()))
            print(f"{c.name}: added {kind} {value}; it is checked within the hour")
        elif args.action == "check":
            n = external.run_due(s, force=args.now)
            print(f"checked {n} targets")
        else:
            for t in s.scalars(select(ExternalTarget).order_by(ExternalTarget.client_id, ExternalTarget.value)):
                issues = s.scalars(select(ExternalIssue).where(ExternalIssue.target_id == t.id, ExternalIssue.status == "open")).all()
                print(f"{t.client_id:>4}  {t.kind:<6} {t.value:<40} {t.last_checked_at or 'not checked'}  {t.last_error or ''}")
                for i in issues:
                    print(f"        {i.severity:<8} {i.title}")
    return 0


def cmd_evaluate(args) -> int:
    with session_scope() as s:
        if args.all:
            findings.mark_all_for_rematch(s)
    total = 0
    while True:
        with session_scope() as s:
            n = findings.evaluate_pending(s)
        if not n:
            break
        total += n
    print(f"evaluated {total} devices")
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

    p = sub.add_parser("client", help="list or add clients")
    p.add_argument("action", choices=["list", "add"])
    p.add_argument("name", nargs="?")

    p = sub.add_parser("site", help="add a site, rotate its enrollment key, or pick its sensor PC")
    sp = p.add_subparsers(dest="action", required=True)
    a = sp.add_parser("sensor", help="pick the enrolled PC that scans the site's network")
    a.add_argument("site_id", type=int)
    a.add_argument("device", help="device id, or 'none' to turn sensor mode off")
    a = sp.add_parser("add")
    a.add_argument("--client", required=True, help="client name")
    a.add_argument("--name", required=True, help="site name")
    a.add_argument("--wua", action="store_true", help="enable the weekly Windows Update cross-check")
    a = sp.add_parser("rotate-key")
    a.add_argument("site_id", type=int)

    p = sub.add_parser("halo", help="HaloPSA tickets: link a client, or sync now")
    hp = p.add_subparsers(dest="action", required=True)
    hp.add_parser("sync", help="create, update and close tickets now (a dry run unless BEARWATCH_HALO_DRY_RUN=false)")
    a = hp.add_parser("client", help="set a client's HaloPSA client id")
    a.add_argument("client_id", type=int)
    a.add_argument("halo_id", help="the client's id in Halo, or 'none'")

    p = sub.add_parser("external", help="a client's public addresses and domains, checked weekly from outside")
    ep = p.add_subparsers(dest="action", required=True)
    a = ep.add_parser("add")
    a.add_argument("client_id", type=int)
    a.add_argument("value", help="a public IP address or a domain name")
    ep.add_parser("list")
    a = ep.add_parser("check", help="check the targets that are due")
    a.add_argument("--now", action="store_true", help="check every target now, due or not")

    p = sub.add_parser("report", help="write a client's monthly report")
    p.add_argument("client_id", type=int)
    p.add_argument("--month", help="YYYY-MM; default: last month")
    p.add_argument("--out", required=True, help="output file")
    p.add_argument("--html", action="store_true", help="write HTML instead of PDF")

    p = sub.add_parser("evaluate", help="recompute findings for devices that need it")
    p.add_argument("--all", action="store_true", help="re-evaluate every device")

    args = ap.parse_args(argv)
    if args.cmd == "client" and args.action == "add" and not args.name:
        ap.error("client add needs a name")
    init_db()
    handlers = {
        "initdb": lambda a: 0,
        "sync": cmd_sync,
        "status": cmd_status,
        "windows": cmd_windows,
        "app": cmd_app,
        "ssvc": cmd_ssvc,
        "overrides": cmd_overrides_check,
        "client": cmd_client,
        "site": cmd_site,
        "evaluate": cmd_evaluate,
        "report": cmd_report,
        "halo": cmd_halo,
        "external": cmd_external,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
