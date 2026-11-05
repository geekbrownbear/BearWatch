"""The monthly client report: a short PDF for a QBR or a cyber insurance renewal.

Everything in it comes from data BearWatch already has. The grade starts at 100 and loses
points for specific, named problems, and the report lists every deduction, so a client can see
exactly what moves it. See docs/report.md.
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import and_, distinct, func, select
from sqlalchemy.orm import Session

from . import lifecycle, posture, scoring, sensor
from .intel.common import utcnow
from .models import Client, Device, ExternalIssue, ExternalTarget, Finding, FindingEvent, NetworkHost, NetworkIssue, Site

SILENT = timedelta(hours=24)

# (points per item, most points in total) for each kind of problem.
PENALTIES = {
    "exploited": (15, 45),  # an update that fixes a known exploited vulnerability, not installed
    "overdue": (5, 25),  # an update past its fix deadline
    "unsupported": (5, 15),  # a PC on a Windows version that no longer gets security updates
    "checklist": (5, 30),  # a failed item on the insurance readiness checklist
    "silent": (2, 10),  # a PC whose agent has not checked in for a day
    "exposed": (10, 30),  # a critical or high issue on the office network or seen from the internet
}
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


def plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def month_bounds(month: date) -> tuple[datetime, datetime]:
    start = datetime(month.year, month.month, 1)
    end = datetime(month.year + (month.month == 12), month.month % 12 + 1, 1)
    return start, end


def previous_month(today: date | None = None) -> date:
    today = today or utcnow().date()
    first = today.replace(day=1)
    return (first - timedelta(days=1)).replace(day=1)


@dataclass
class CheckItem:
    title: str
    status: str  # pass | fail | unknown
    detail: str


@dataclass
class Report:
    client: Client
    month: date
    generated: datetime
    as_of: datetime
    devices: int = 0
    servers: int = 0
    silent: list[str] = field(default_factory=list)
    open_findings: int = 0
    open_fixes: int = 0
    exploited_fixes: int = 0
    overdue_fixes: int = 0
    found: int = 0
    fixed: int = 0
    fixed_on_time: int = 0
    trend: list[dict] = field(default_factory=list)
    top_fixes: list[dict] = field(default_factory=list)
    windows: list[dict] = field(default_factory=list)
    settings: list[dict] = field(default_factory=list)
    network: dict = field(default_factory=dict)
    network_issues: list[dict] = field(default_factory=list)
    external: dict = field(default_factory=dict)
    settings_checked: int = 0  # PCs whose settings could be judged at all
    checklist: list[CheckItem] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    deductions: list[tuple[int, str]] = field(default_factory=list)

    @property
    def on_time_rate(self) -> int | None:
        return round(100 * self.fixed_on_time / self.fixed) if self.fixed else None


def _client_devices(s: Session, client_id: int) -> list[Device]:
    return list(s.scalars(select(Device).join(Site, Site.id == Device.site_id).where(Site.client_id == client_id)
                          .order_by(func.lower(Device.hostname))))


def _status_at(s: Session, device_ids: list[int], when: datetime) -> int:
    """How many findings were open at `when`, replayed from found/fixed/reopened events."""
    if not device_ids:
        return 0
    last: dict[int, str] = {}
    q = (select(FindingEvent.finding_id, FindingEvent.event).where(FindingEvent.device_id.in_(device_ids), FindingEvent.at < when)
         .order_by(FindingEvent.at, FindingEvent.id))
    for fid, ev in s.execute(q):
        last[fid] = ev
    return sum(1 for ev in last.values() if ev in ("found", "reopened"))


def _cycle_deadline(s: Session, finding_id: int, fixed_at: datetime) -> datetime:
    """The deadline that applied to the fix at `fixed_at`: the start of that open cycle (its
    found or reopened event) plus the fix window. A finding that reopens later gets a new
    deadline, which must not rewrite how an older fix is judged."""
    f = s.get(Finding, finding_id)
    began = s.scalar(select(func.max(FindingEvent.at)).where(FindingEvent.finding_id == finding_id,
                                                             FindingEvent.event.in_(("found", "reopened")),
                                                             FindingEvent.at <= fixed_at))
    began = began or (f.first_seen if f is not None else fixed_at)
    tier, cvss = (f.exploit_tier, f.cvss) if f is not None else (4, None)
    return began + timedelta(days=scoring.sla_days(tier, cvss))


def build(s: Session, client_id: int, month: date, now: datetime | None = None) -> Report:
    now = now or utcnow()
    client = s.get(Client, client_id)
    if client is None:
        raise LookupError(f"no client {client_id}")
    start, end = month_bounds(month)
    as_of = min(end, now)
    r = Report(client=client, month=start.date(), generated=now, as_of=as_of)

    devs = _client_devices(s, client_id)
    ids = [d.id for d in devs]
    r.devices, r.servers = len(devs), sum(1 for d in devs if d.is_server)
    r.silent = [d.hostname for d in devs if d.last_seen is None or now - d.last_seen > SILENT]

    # Open work right now (the report describes the state on the day it is made).
    open_q = select(Finding).where(Finding.device_id.in_(ids), Finding.status == "open") if ids else None
    open_f = list(s.scalars(open_q)) if ids else []
    r.open_findings = len(open_f)
    fixes: dict[str, dict] = {}
    for f in open_f:
        g = fixes.setdefault(f.fix_key, {"label": f.fix_label, "devices": set(), "cves": set(), "tier": 4, "risk": 0.0,
                                         "overdue": False, "source": f.source})
        g["devices"].add(f.device_id)
        if f.source != "posture":
            g["cves"].add(f.cve_id)
        g["tier"] = min(g["tier"], f.exploit_tier)
        g["risk"] = max(g["risk"], f.risk or 0.0)
        if f.due_at is not None and f.due_at < now and f.exception_id is None:
            g["overdue"] = True
            if f.exploit_tier == 1:
                g["exploited_late"] = True
    r.open_fixes = len(fixes)
    r.exploited_fixes = sum(1 for g in fixes.values() if g["tier"] == 1)
    r.overdue_fixes = sum(1 for g in fixes.values() if g["overdue"])
    top = sorted(fixes.values(), key=lambda g: (-g["risk"], g["tier"], -len(g["devices"]), g["label"]))[:5]
    r.top_fixes = [{**g, "devices": len(g["devices"]), "cves": len(g["cves"])} for g in top]

    # The month: what was found and fixed, and how many fixes beat their deadline.
    if ids:
        events = s.execute(select(FindingEvent.event, FindingEvent.finding_id, FindingEvent.at)
                           .where(FindingEvent.device_id.in_(ids), FindingEvent.at >= start, FindingEvent.at < end)).all()
        r.found = sum(1 for ev, _, _ in events if ev in ("found", "reopened"))
        fixed = [(fid, at) for ev, fid, at in events if ev == "fixed"]
        r.fixed = len(fixed)
        r.fixed_on_time = sum(1 for fid, at in fixed if at <= _cycle_deadline(s, fid, at))

    # Six months of trend, ending with this one.
    m = start.date()
    months = []
    for _ in range(6):
        months.append(m)
        m = (m - timedelta(days=1)).replace(day=1)
    for mo in reversed(months):
        a, b = month_bounds(mo)
        if ids:
            found = s.scalar(select(func.count()).select_from(FindingEvent)
                             .where(FindingEvent.device_id.in_(ids), FindingEvent.event.in_(("found", "reopened")),
                                    FindingEvent.at >= a, FindingEvent.at < b)) or 0
            fixed_n = s.scalar(select(func.count()).select_from(FindingEvent)
                               .where(FindingEvent.device_id.in_(ids), FindingEvent.event == "fixed",
                                      FindingEvent.at >= a, FindingEvent.at < b)) or 0
        else:
            found = fixed_n = 0
        r.trend.append({"month": mo, "found": found, "fixed": fixed_n, "open": _status_at(s, ids, min(b, now))})

    # Windows versions and their support.
    by_version: dict[tuple, dict] = {}
    for d in devs:
        sup = lifecycle.support(d.os_build, d.os_caption, d.is_server, now.date())
        key = (sup.name, sup.status, sup.ends)
        row = by_version.setdefault(key, {"name": sup.name, "status": sup.status, "label": sup.label, "devices": []})
        row["devices"].append(d.hostname)
    order = {"ended": 0, "ending": 1, "unknown": 2, "supported": 3}
    r.windows = sorted(by_version.values(), key=lambda v: (order[v["status"]], v["name"]))
    unsupported = [h for v in r.windows if v["status"] == "ended" for h in v["devices"]]
    unknown_support = [h for v in r.windows if v["status"] == "unknown" for h in v["devices"]]

    # Windows settings that fail, by how many PCs.
    if ids:
        q = (select(Finding.subject_key, func.max(Finding.subject), func.count(distinct(Finding.device_id)))
             .where(Finding.device_id.in_(ids), Finding.source == "posture", Finding.status == "open")
             .group_by(Finding.subject_key).order_by(func.count(distinct(Finding.device_id)).desc(), Finding.subject_key))
        r.settings = [{"rule": k, "title": t, "devices": n} for k, t, n in s.execute(q)]
    failing = {x["rule"]: x["devices"] for x in r.settings}

    # Network (sensor).
    sites = list(s.scalars(select(Site).where(Site.client_id == client_id)))
    scanned = [site for site in sites if site.sensor_device_id and site.sensor_scan_at]
    has_sensor = bool(scanned)
    unscanned = [site.name for site in sites if site not in scanned]
    hosts = s.execute(select(NetworkHost, Site).join(Site, Site.id == NetworkHost.site_id)
                      .where(Site.client_id == client_id, NetworkHost.last_seen >= now - timedelta(days=30))).all()
    r.network = {
        "sensor": has_sensor,
        "unscanned": unscanned,
        "hosts": len(hosts),
        "unmanaged": sum(1 for h, _ in hosts if h.device_id is None),
        "new": sum(1 for h, site in hosts if sensor.is_new(h, site, now)),
    }
    issues = s.execute(select(NetworkIssue, NetworkHost).join(NetworkHost, NetworkHost.id == NetworkIssue.host_id)
                       .join(Site, Site.id == NetworkHost.site_id)
                       .where(Site.client_id == client_id, NetworkIssue.status == "open", sensor.issue_clause())
                       .order_by(NetworkIssue.cvss.desc().nulls_last())).all()
    r.network_issues = [{"title": i.title, "host": h.name or h.ip, "ip": h.ip, "port": i.port, "severity": sensor.severity(i.cvss),
                         "solution": i.solution} for i, h in issues]
    serious_net = sum(1 for x in r.network_issues if x["severity"] in ("critical", "high"))

    # Insurance readiness: things insurers ask about, answered only from what BearWatch measured.
    # Each rule is judged on each PC's own values. A PC whose agent sent no settings, or that
    # lacks a value the rule reads, is "not checked", so the item can't be a "Yes".
    rs = posture.ruleset()
    judged = {d.id: ({x.rule.id: x.status for x in posture.evaluate(rs, d.posture.get("values", {}), d.is_server,
                                                                     posture.build_number(d.os_build))}
                     if d.posture is not None else None) for d in devs}

    r.settings_checked = sum(1 for d in devs if judged[d.id] and any(v != "unknown" for v in judged[d.id].values()))

    def setting(rules: list[str], title: str, ok: str, bad: str, workstations_only: bool = False) -> CheckItem:
        if not ids:
            return CheckItem(title, "unknown", "No PCs report to BearWatch yet.")
        pool = [d for d in devs if not (workstations_only and d.is_server)]
        fails = unknown = passes = 0
        for d in pool:
            res = judged[d.id]
            if res is None:
                unknown += 1
                continue
            sts = [res[x] for x in rules if x in res]  # missing: the rule doesn't apply to this PC
            if "fail" in sts:
                fails += 1
            elif "unknown" in sts or (not sts and not any(x in rs.by_id for x in rules)):
                unknown += 1
            else:
                passes += 1
        if fails:
            return CheckItem(title, "fail", bad.format(pcs=plural(fails, "PC"), workstations=plural(fails, "workstation"),
                                                       verb="has" if fails == 1 else "have"))
        if unknown:
            if not passes:
                return CheckItem(title, "unknown", "Not checked yet. The agents on these PCs need an update first.")
            return CheckItem(title, "unknown", f"Passes on {plural(passes, 'PC')}; {plural(unknown, 'PC')} not checked yet.")
        return CheckItem(title, "pass", ok)

    # Seen from the internet (external.py).
    # Every listed target counts. One that has never been checked successfully, or whose last
    # check failed, is unverified: it can fail an item but never let it pass.
    targets = s.scalars(select(ExternalTarget).where(ExternalTarget.client_id == client_id)).all()
    t_ids = [t.id for t in targets]
    ext_open = {(i.target_id, i.check_id) for i in s.scalars(select(ExternalIssue).where(ExternalIssue.target_id.in_(t_ids),
                                                                                        ExternalIssue.status == "open"))} if t_ids else set()
    ips = [t for t in targets if t.kind == "ip"]
    domains = [t for t in targets if t.kind == "domain"]
    remote_ports = {"port-3389", "port-445", "port-23", "port-5900", "port-135", "port-139"}
    exposed = sorted({t.value for t in ips if any((t.id, c) in ext_open for c in remote_ports)})
    spoofable = sorted({t.value for t in domains if any((t.id, c) in ext_open for c in ("spf-missing", "spf-allows-all", "dmarc-missing"))})
    unverified_ips = [t.value for t in ips if t.snapshot is None or t.last_error]
    unverified_domains = [t.value for t in domains if t.snapshot is None or t.last_error]
    r.external = {"ips": len(ips), "domains": len(domains), "exposed": exposed, "spoofable": spoofable}
    serious_ext = sum(1 for i in s.scalars(select(ExternalIssue).where(ExternalIssue.target_id.in_(t_ids), ExternalIssue.status == "open",
                                                                       ExternalIssue.severity.in_(("critical", "high"))))) if t_ids else 0

    def ext_item(title: str, items: list, bad: list[str], unverified: list[str], bad_text: str, ok_text: str, none_text: str) -> CheckItem:
        if bad:
            return CheckItem(title, "fail", bad_text.format(", ".join(bad)))
        if not items:
            return CheckItem(title, "unknown", none_text)
        if unverified:
            return CheckItem(title, "unknown", f"Not checked yet: {', '.join(unverified)}.")
        return CheckItem(title, "pass", ok_text)

    known_late = any(g.get("exploited_late") for g in fixes.values())
    r.checklist = [
        setting(["av-unhealthy"], "Antivirus is on and up to date", "On and up to date on every workstation.",
                "Off or out of date on {workstations}.", workstations_only=True),
        setting(["firewall-off"], "Windows Firewall is on", "On for every network type on every PC.", "Off on {pcs}."),
        setting(["rdp-without-nla"], "Remote Desktop requires sign-in first", "Every PC requires it, or has Remote Desktop off.",
                "{pcs} accept Remote Desktop without it."),
        setting(["smb1-server", "smb1-client"], "Old SMBv1 file sharing is off", "Off on every PC.", "Still on for {pcs}."),
        setting(["laps-missing"], "Local admin passwords are unique and rotated", "Every PC uses LAPS.", "{pcs} {verb} no LAPS."),
        CheckItem("Every PC runs a supported Windows version",
                  "fail" if unsupported else ("unknown" if unknown_support or not ids else "pass"),
                  f"{plural(len(unsupported), 'PC')} no longer {'gets' if len(unsupported) == 1 else 'get'} security updates." if unsupported
                  else f"Support dates are unknown for {plural(len(unknown_support), 'PC')}." if unknown_support
                  else "Every PC still gets security updates." if ids else "No PCs report to BearWatch yet."),
        CheckItem("Known exploited vulnerabilities are fixed within 14 days",
                  "fail" if known_late else ("pass" if ids else "unknown"),
                  "Some are past their 14-day deadline." if known_late
                  else "None are past their deadline." if ids else "No PCs report to BearWatch yet."),
        CheckItem("Every PC is monitored", "fail" if r.silent else ("pass" if ids else "unknown"),
                  f"{plural(len(r.silent), 'PC')} {'has' if len(r.silent) == 1 else 'have'} not checked in for a day." if r.silent
                  else "Every PC checked in within the last day." if ids else "No PCs report to BearWatch yet."),
        ext_item("Remote access and file sharing are closed to the internet", ips, exposed, unverified_ips,
                 "Open on {}.", f"Closed on {plural(len(ips), 'public address')}.", "No public addresses listed for this client yet."),
        ext_item("Email is protected from spoofing (SPF and DMARC)", domains, spoofable, unverified_domains,
                 "Missing for {}.", f"Set up for {plural(len(domains), 'domain')}.", "No email domains listed for this client yet."),
        CheckItem("No unsafe services on the office network",
                  "fail" if serious_net else ("unknown" if unscanned or not sites else "pass"),
                  f"{plural(serious_net, 'serious issue')} found." if serious_net
                  else (f"No network scan yet at {', '.join(unscanned)}." if has_sensor else "No network sensor at this office yet.")
                  if unscanned or not sites else "None found in the last scan."),
    ]

    # The grade. Items already counted above (Windows support, silent PCs, exploited updates) are
    # left out of the checklist deduction so nothing costs points twice.
    def take(kind: str, count: int, text: str) -> None:
        if count <= 0:
            return
        each, most = PENALTIES[kind]
        r.deductions.append((min(each * count, most), text))

    n = r.exploited_fixes
    take("exploited", n, f"{plural(n, 'update')} that {'fixes' if n == 1 else 'fix'} vulnerabilities attackers are using, not installed")
    n = r.overdue_fixes
    take("overdue", n, f"{plural(n, 'update')} past the fix deadline")
    n = len(unsupported)
    take("unsupported", n, f"{plural(n, 'PC')} on a Windows version that no longer gets security updates")
    # Items already counted on their own (Windows support, silent PCs, exploited updates, serious
    # network and internet issues) are left out here so nothing costs points twice.
    n = serious_net + serious_ext
    take("exposed", n, f"{plural(n, 'serious issue')} on the office network or open to the internet")
    fails = [c for c in r.checklist if c.status == "fail" and not c.title.startswith(
        ("Every PC runs", "Every PC is", "Known exploited", "No unsafe services", "Remote access"))]
    take("checklist", len(fails), f"{plural(len(fails), 'insurance checklist item')} not met")
    n = len(r.silent)
    take("silent", n, f"{plural(n, 'PC')} not checking in")
    r.score = max(0, 100 - sum(p for p, _ in r.deductions))
    r.grade = next((g for floor, g in GRADES if r.score >= floor), "F")
    return r


# --- rendering ------------------------------------------------------------------------------


def _fmt_date(d) -> str:
    return f"{d:%B} {d.day}, {d.year}"


def render_html(r: Report, screen: bool = False, static: str | None = None) -> str:
    """The report as one HTML page. `static` is where the fonts and logo load from: a URL path
    for the browser preview, a file:// URL for WeasyPrint."""
    from .web import STATIC, templates

    tpl = templates.env.get_template("report.html")
    return tpl.render(r=r, screen=screen, static=static or STATIC.as_uri(), fmt_date=_fmt_date,
                      month_name=f"{r.month:%B %Y}", month_short=f"{r.month:%B}")


def pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError):  # OSError: the Pango libraries are missing
        return False
    return True


def render_pdf(r: Report) -> bytes:
    import logging

    from weasyprint import HTML

    for name in ("weasyprint", "fontTools"):  # page-by-page progress and font subsetting chatter
        logging.getLogger(name).setLevel(logging.WARNING)

    from .web import STATIC

    return HTML(string=render_html(r), base_url=STATIC.as_uri() + "/").write_pdf()
