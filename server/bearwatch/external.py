"""External exposure: what a client looks like from the internet, without scanning anything.

A technician lists a client's public IP addresses and domains. Once a week each one is checked:

- IP addresses: Shodan InternetDB (free, no key) says which ports the internet sees open and
  which CVEs Shodan matched to the banners. Remote Desktop, file sharing, databases and the like
  open to the internet become issues; a port that was not open last week is flagged as new.
- Domains: SPF and DMARC (email spoofing), DNSSEC, read through DNS over HTTPS, and the website's
  certificate expiry from one ordinary TLS connection.

Nothing here sends a probe to the client's network. Active scanning (port sweeps, nuclei) needs
the client's written permission and is a separate decision. See docs/external.md.
"""

import ipaddress
import logging
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .intel.common import utcnow
from .models import ExternalIssue, ExternalTarget, Kev

log = logging.getLogger("bearwatch.external")
INTERNETDB = "https://internetdb.shodan.io/{ip}"
DOH = "https://cloudflare-dns.com/dns-query"
EVERY = timedelta(days=7)
NEW_FOR = timedelta(days=7)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Ports that should not be open to the internet on a small business network. (From Bearium
# Cyber Scan's network module.)
RISKY_PORTS = {
    21: ("FTP", "high"), 23: ("Telnet", "critical"), 135: ("Windows RPC", "high"), 137: ("NetBIOS", "high"),
    139: ("NetBIOS file sharing", "high"), 445: ("Windows file sharing (SMB)", "critical"),
    1433: ("Microsoft SQL Server", "high"), 1521: ("Oracle database", "high"), 3306: ("MySQL database", "high"),
    3389: ("Remote Desktop (RDP)", "critical"), 5432: ("PostgreSQL database", "high"), 5900: ("VNC remote control", "critical"),
    6379: ("Redis database", "high"), 9200: ("Elasticsearch", "high"), 11211: ("Memcached", "high"), 27017: ("MongoDB database", "high"),
}
# Cloudflare answers on these on every edge address, for every customer: not the client's exposure.
CLOUDFLARE_PORTS = {2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880}
_CF_MARKERS = {2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}


@dataclass
class Found:
    check_id: str
    title: str
    severity: str  # critical | high | medium | low
    detail: str
    solution: str


def normalize(value: str) -> tuple[str, str]:
    """('ip', '203.0.113.5') or ('domain', 'example.com'). Raises ValueError for anything else,
    including private addresses: the point is what the internet sees."""
    v = value.strip().lower().rstrip(".")
    v = re.sub(r"^https?://", "", v).split("/")[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        if DOMAIN_RE.match(v):
            return "domain", v
        raise ValueError(f"{value!r} is not a public IP address or a domain name") from None
    if not ip.is_global:
        raise ValueError(f"{ip} is not a public address")
    return "ip", str(ip)


# --- IP addresses -----------------------------------------------------------------------------


def check_ip(http: httpx.Client, ip: str, kev: set[str]) -> tuple[dict, list[Found]]:
    r = http.get(INTERNETDB.format(ip=ip))
    if r.status_code == 404:  # Shodan has seen nothing open on it
        data = {"ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
    elif r.status_code == 200:
        data = r.json()
    else:
        raise RuntimeError(f"InternetDB answered HTTP {r.status_code}")
    ports = {int(p) for p in data.get("ports") or []}
    names = {str(h).lower() for h in data.get("hostnames") or []}
    tags = {str(t).lower() for t in data.get("tags") or []}
    if len(ports & _CF_MARKERS) >= 4 or any("cloudflare" in x for x in names | tags):
        ports -= CLOUDFLARE_PORTS
    vulns = sorted({str(v).upper() for v in data.get("vulns") or []})
    found = []
    for p in sorted(ports & RISKY_PORTS.keys()):
        name, sev = RISKY_PORTS[p]
        found.append(Found(f"port-{p}", f"{name} is open to the internet", sev,
                           f"Port {p} on {ip} answers from the internet.",
                           "Close the port on the firewall, or allow it only from known addresses or through a VPN."))
    if vulns:
        exploited = [v for v in vulns if v in kev]
        shown = ", ".join((exploited or vulns)[:10]) + (" and more" if len(vulns) > 10 else "")
        found.append(Found("shodan-cves", f"Shodan matched {len(vulns)} known {'vulnerability' if len(vulns) == 1 else 'vulnerabilities'} to this address",
                           "high" if exploited else "medium",
                           (f"{len(exploited)} of them are known exploited: " if exploited else "") + shown + ". Shodan guesses these from "
                           "software banners, so check the version on the device before acting.",
                           "Update the software on the device that answers on this address, or close its port."))
    snapshot = {"ports": sorted(ports), "vulns": vulns, "hostnames": sorted(names)[:20], "tags": sorted(tags)[:20]}
    return snapshot, found


# --- domains ----------------------------------------------------------------------------------


def _txt(http: httpx.Client, name: str) -> tuple[list[str], bool]:
    """TXT records for name, and whether the answer was DNSSEC-validated (AD flag)."""
    r = http.get(DOH, params={"name": name, "type": "TXT"}, headers={"accept": "application/dns-json"})
    if r.status_code != 200:
        raise RuntimeError(f"DNS lookup for {name} answered HTTP {r.status_code}")
    body = r.json()
    # 0 is an answer; 3 (NXDOMAIN) means the name has no records, which is an answer too (a
    # domain with no _dmarc record). Anything else (SERVFAIL, REFUSED) is a failed lookup, and
    # must not be read as "no SPF".
    if body.get("Status") not in (0, 3):
        raise RuntimeError(f"DNS lookup for {name} failed (status {body.get('Status')})")
    out = [a.get("data", "").replace('" "', "").strip('"') for a in body.get("Answer") or [] if a.get("type") == 16]
    return out, bool(body.get("AD"))


def check_domain(http: httpx.Client, domain: str, cert_days_left=None) -> tuple[dict, list[Found]]:
    found = []
    txt, ad = _txt(http, domain)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        found.append(Found("spf-missing", "No SPF record, so anyone can send email as this domain", "medium",
                           f"{domain} has no SPF record.", "Add an SPF record that lists the services allowed to send its email."))
    elif any(re.search(r"(^|\s)\+?all(\s|$)", s.lower()) for s in spf):
        found.append(Found("spf-allows-all", "The SPF record allows any server to send email", "high",
                           f"{domain}: {spf[0][:200]}", "End the SPF record with -all or ~all instead of +all."))
    dmarc, _ = _txt(http, f"_dmarc.{domain}")
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        found.append(Found("dmarc-missing", "No DMARC record, so spoofed email is not blocked", "medium",
                           f"_dmarc.{domain} has no DMARC record.", "Add a DMARC record. Start with p=none to collect reports, then move to quarantine."))
    elif re.search(r"\bp\s*=\s*none\b", dmarc[0].lower()):
        found.append(Found("dmarc-monitor-only", "DMARC only monitors, so spoofed email still gets through", "low",
                           f"_dmarc.{domain}: {dmarc[0][:200]}", "Move the DMARC policy to p=quarantine or p=reject once reports look clean."))
    if not ad:
        found.append(Found("dnssec-off", "DNSSEC is not turned on", "low", f"{domain} answers without DNSSEC validation.",
                           "Turn on DNSSEC at the DNS host and add the DS record at the registrar."))
    days = (cert_days_left or cert_days)(domain)
    if days is not None:
        if days < 0:
            found.append(Found("cert-expired", "The website certificate has expired", "critical",
                               f"https://{domain} has a certificate that expired {-days} days ago.", "Renew the certificate now."))
        elif days < 14:
            found.append(Found("cert-expiring", "The website certificate expires within two weeks", "high",
                               f"https://{domain}: {days} days left.", "Renew the certificate, or check why automatic renewal stopped."))
    return {"spf": spf[:1], "dmarc": dmarc[:1], "dnssec": ad, "cert_days_left": days}, found


def cert_days(domain: str, timeout: float = 10.0) -> int | None:
    """Days until the certificate on https://domain expires. None if there is no HTTPS site."""
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # read the date even from a bad cert
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=domain) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    return (cert.not_valid_after_utc.replace(tzinfo=None) - utcnow()).days


# --- running ----------------------------------------------------------------------------------


def due(s: Session, now: datetime | None = None) -> list[ExternalTarget]:
    now = now or utcnow()
    return [t for t in s.scalars(select(ExternalTarget)) if t.last_checked_at is None or now - t.last_checked_at >= EVERY]


def check(s: Session, t: ExternalTarget, http: httpx.Client, cert_days_left=None, now: datetime | None = None) -> None:
    """Measure first, then write. Nothing is changed in the session until the lookups are done:
    with SQLite, a pending change would be flushed by the next query and hold the database's one
    write lock through every slow lookup and TLS wait."""
    now = now or utcnow()
    inconclusive: set[str] = set()
    kev = set(s.scalars(select(Kev.cve_id))) if t.kind == "ip" else set()
    try:
        if t.kind == "ip":
            snap, found = check_ip(http, t.value, kev)
            first = dict((t.snapshot or {}).get("first_seen", {}))
            for p in snap["ports"]:
                first.setdefault(str(p), now.isoformat())
            snap["first_seen"] = {p: v for p, v in first.items() if int(p) in snap["ports"]}
        else:
            snap, found = check_domain(http, t.value, cert_days_left)
            if snap["cert_days_left"] is None:
                # No certificate read this time (timeout, handshake failure, no site). That is not
                # a renewal: keep any certificate issue as it was, and the last known days left.
                inconclusive = {"cert-expired", "cert-expiring"}
                snap["cert_days_left"] = (t.snapshot or {}).get("cert_days_left")
    except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as e:
        t.last_checked_at = now
        t.last_error = str(e)[:500]  # issues stay as they were: no answer is not a fix
        log.warning("external check of %s failed: %s", t.value, e)
        return
    t.last_checked_at = now
    if t.first_checked_at is None:
        t.first_checked_at = now
    t.snapshot, t.last_error = snap, None
    rows = {i.check_id: i for i in s.scalars(select(ExternalIssue).where(ExternalIssue.target_id == t.id))}
    seen = set()
    for f in found:
        seen.add(f.check_id)
        row = rows.get(f.check_id)
        if row is None:
            row = ExternalIssue(target_id=t.id, check_id=f.check_id, first_seen=now)
            s.add(row)
        elif row.status == "fixed":
            row.first_seen = now
        row.title, row.severity, row.detail, row.solution = f.title, f.severity, f.detail, f.solution
        row.status, row.last_seen, row.fixed_at = "open", now, None
    for key, row in rows.items():
        if key not in seen and row.status == "open" and key not in inconclusive:
            row.status, row.fixed_at = "fixed", now
    s.flush()


def run_due(s: Session, http: httpx.Client | None = None) -> int:
    targets = due(s)
    if not targets:
        return 0
    own = http is None
    http = http or httpx.Client(timeout=20, headers={"User-Agent": get_settings().user_agent})
    try:
        for t in targets:
            check(s, t, http)
            s.commit()  # one short write per target, never one held across the next target's lookups
    finally:
        if own:
            http.close()
    return len(targets)


def new_ports(t: ExternalTarget, now: datetime | None = None) -> list[int]:
    """Ports first seen after the target's first check, within the last week."""
    now = now or utcnow()
    snap = t.snapshot or {}
    if t.first_checked_at is None:
        return []
    out = []
    for p, when in (snap.get("first_seen") or {}).items():
        at = datetime.fromisoformat(when)
        if at > t.first_checked_at and now - at < NEW_FOR:
            out.append(int(p))
    return sorted(out)
