"""HaloPSA tickets: one ticket per fix per client, kept up to date, closed when verified fixed.

Every 15 minutes the worker looks at each client that has a Halo client id. A fix (one KB, one
app update, one setting) that is serious enough gets a ticket listing the PCs and CVEs it
covers and its deadline. When that list changes, the ticket is updated with a private note.
When no PC needs the fix any more (BearWatch saw it fixed, not just a technician saying so), the
ticket is closed with a note. A fix that comes back gets a new ticket.

All Halo API calls are in HaloApi, so checking them against an instance's own API reference
(https://<instance>/apidoc) means reading one class. Set BEARWATCH_HALO_DRY_RUN=false only after
that check; until then `bearwatch halo sync` prints what it would do and changes nothing.
"""

import hashlib
import logging
import time
from urllib.parse import urlencode
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .intel.common import utcnow
from .models import Client, Device, Finding, HaloTicket, Site

log = logging.getLogger("bearwatch.halo")
SUMMARY_MAX = 70  # Halo shows about this much in ticket lists


# --- the API ---------------------------------------------------------------------------------


class HaloError(RuntimeError):
    pass


class HaloApi:
    """The five calls BearWatch makes. Halo's API takes and returns JSON; ticket and action
    writes are POSTed as a list, and "id" in a ticket object makes the POST an update."""

    def __init__(self, url: str, client_id: str, client_secret: str, tenant: str = "", http: httpx.Client | None = None):
        self.url = url.rstrip("/")
        self.client_id, self.client_secret, self.tenant = client_id, client_secret, tenant
        self.http = http or httpx.Client(timeout=30)
        self._token: str | None = None
        self._expires = 0.0

    def _auth(self) -> dict:
        if self._token is None or time.monotonic() > self._expires - 60:
            data = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret, "scope": "all"}
            if self.tenant:
                data["tenant"] = self.tenant
            r = self.http.post(f"{self.url}/auth/token", data=data)
            if r.status_code != 200:
                raise HaloError(f"sign-in failed: HTTP {r.status_code}")
            body = r.json()
            self._token = body["access_token"]
            self._expires = time.monotonic() + float(body.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self._token}"}

    def _post(self, path: str, items: list[dict]) -> dict:
        r = self.http.post(f"{self.url}/api/{path}", json=items, headers=self._auth())
        if r.status_code not in (200, 201):
            raise HaloError(f"POST /api/{path}: HTTP {r.status_code} {r.text[:300]}")
        body = r.json()
        return body[0] if isinstance(body, list) and body else body

    def create_ticket(self, ticket: dict) -> int:
        return int(self._post("tickets", [ticket])["id"])

    def update_ticket(self, ticket_id: int, fields: dict) -> None:
        self._post("tickets", [{"id": ticket_id, **fields}])

    def add_note(self, ticket_id: int, note: str, outcome: str) -> None:
        self._post("actions", [{"ticket_id": ticket_id, "note": note, "outcome": outcome, "hiddenfromuser": True}])

    def ticket_open(self, ticket_id: int, closed_status_id: int) -> bool:
        """False when a technician already closed it in Halo."""
        r = self.http.get(f"{self.url}/api/tickets/{ticket_id}", headers=self._auth())
        if r.status_code == 404:
            return False
        if r.status_code != 200:
            raise HaloError(f"GET /api/tickets/{ticket_id}: HTTP {r.status_code}")
        return int(r.json().get("status_id", 0)) != closed_status_id


@dataclass
class DryRunApi:
    """Records what would be sent. Used until BEARWATCH_HALO_DRY_RUN is turned off."""

    calls: list[tuple] = field(default_factory=list)
    _next: int = -1

    def create_ticket(self, ticket: dict) -> int:
        self.calls.append(("create", ticket["summary"]))
        self._next -= 1
        return self._next  # negative: never a real Halo id

    def update_ticket(self, ticket_id: int, fields: dict) -> None:
        self.calls.append(("update", ticket_id, sorted(fields)))

    def add_note(self, ticket_id: int, note: str, outcome: str) -> None:
        self.calls.append(("note", ticket_id, note.splitlines()[0]))

    def ticket_open(self, ticket_id: int, closed_status_id: int) -> bool:
        return True


def api_from_settings():
    cfg = get_settings()
    if not configured():
        return None
    if cfg.halo_dry_run:
        return DryRunApi()
    return HaloApi(cfg.halo_url, cfg.halo_client_id, cfg.halo_client_secret, cfg.halo_tenant)


def configured() -> bool:
    cfg = get_settings()
    return bool(cfg.halo_url and cfg.halo_client_id and cfg.halo_client_secret)


# --- what deserves a ticket ------------------------------------------------------------------


@dataclass
class Group:
    fix_key: str
    label: str
    tier: int  # from findings without an exception only
    risk: float
    due: datetime | None
    devices: dict[int, str]  # device id -> "HOSTNAME (site)"; ids, since hostnames can repeat
    cves: list[str]

    @property
    def digest(self) -> str:
        """Everything the ticket shows: a change in any of it rewrites the ticket. PCs are keyed
        by id, with the name shown, so a renamed PC updates the list too."""
        parts = ([self.label, "#"] + [f"{i}={self.devices[i]}" for i in sorted(self.devices)] + ["#"] + self.cves
                 + ["#", str(self.tier), self.due.isoformat() if self.due else "-"])
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    @property
    def device_names(self) -> list[str]:
        return sorted(self.devices.values(), key=str.lower)


def open_groups(s: Session, client_id: int) -> dict[str, Group]:
    q = (select(Finding, Device.hostname, Site.name).join(Device, Device.id == Finding.device_id).join(Site, Site.id == Device.site_id)
         .where(Site.client_id == client_id, Finding.status == "open"))
    groups: dict[str, Group] = {}
    for f, host, site in s.execute(q):
        g = groups.setdefault(f.fix_key, Group(f.fix_key, f.fix_label, 4, 0.0, None, {}, []))
        if f.exception_id is None:  # an excepted finding (false positive, accepted risk) doesn't make the fix urgent
            g.tier = min(g.tier, f.exploit_tier)
            g.risk = max(g.risk, f.risk or 0.0)
            if f.due_at is not None and (g.due is None or f.due_at < g.due):
                g.due = f.due_at
        g.devices[f.device_id] = f"{host} ({site})"
        if f.source != "posture" and f.cve_id not in g.cves:
            g.cves.append(f.cve_id)
    for g in groups.values():
        g.cves.sort()
    return groups


def wanted(g: Group, min_risk: float, now: datetime) -> bool:
    """Serious enough for a ticket: known exploited, high risk, or past its deadline."""
    return g.risk > 0 and (g.tier == 1 or g.risk >= min_risk or (g.due is not None and g.due < now))


def _details(g: Group, client: Client, base_url: str) -> str:
    lines = [f"BearWatch found that {len(g.devices)} {'PC needs' if len(g.devices) == 1 else 'PCs need'} this fix.", ""]
    if g.due:
        lines.append(f"Fix by: {g.due:%B} {g.due.day}, {g.due.year}")
    if g.tier == 1:
        lines.append("Attackers are using at least one of these vulnerabilities now (known exploited).")
    lines += ["", "PCs:"] + [f"- {h}" for h in g.device_names]
    if g.cves:
        shown = g.cves[:40]
        lines += ["", f"Vulnerabilities ({len(g.cves)}):", ", ".join(shown) + (" and more" if len(g.cves) > len(shown) else "")]
    if base_url:
        # Encoded: fix keys can hold "+" (winget:Notepad++.Notepad++), which a query string reads as a space.
        lines += ["", f"Details: {base_url.rstrip('/')}/fix?{urlencode({'key': g.fix_key, 'client': client.id})}"]
    lines += ["", "BearWatch updates this ticket when the list changes and closes it once every PC is fixed."]
    return "\n".join(lines)


def _summary(g: Group) -> str:
    s = f"BearWatch: {g.label}"
    return s if len(s) <= SUMMARY_MAX else s[: SUMMARY_MAX - 3].rstrip() + "..."


# --- the sync --------------------------------------------------------------------------------


LOCK_KEY = 0x48414C4F  # "HALO": one sync at a time across the worker and the CLI


def _lock(s: Session) -> None:
    """Serialize syncs, so the worker and `bearwatch halo sync` can't both see no ticket and both
    create one. Held until the transaction ends. SQLite (tests) has one writer anyway."""
    if s.get_bind().dialect.name == "postgresql":
        s.execute(text("select pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})


def sync(s: Session, api) -> int:
    """Create, update and close tickets for every client with a Halo client id. Returns how many
    tickets were touched. One failing ticket is recorded on its row and does not stop the rest."""
    _lock(s)
    cfg, now = get_settings(), utcnow()
    touched = 0
    for client in s.scalars(select(Client).where(Client.halo_client_id.is_not(None))):
        groups = open_groups(s, client.id)
        rows = {t.fix_key: t for t in s.scalars(select(HaloTicket).where(HaloTicket.client_id == client.id))}
        for key, g in groups.items():
            row = rows.get(key)
            if not wanted(g, cfg.halo_min_risk, now) and (row is None or row.status != "open"):
                continue
            try:
                if row is None or row.status != "open":
                    ticket = {"summary": _summary(g), "details": _details(g, client, cfg.public_url), "client_id": client.halo_client_id}
                    if cfg.halo_ticket_type_id:
                        ticket["tickettype_id"] = cfg.halo_ticket_type_id
                    hid = api.create_ticket(ticket)
                    if row is None:
                        row = HaloTicket(client_id=client.id, fix_key=key)
                        s.add(row)
                    row.halo_id, row.status, row.digest, row.opened_at, row.closed_at = hid, "open", g.digest, now, None
                    touched += 1
                elif not api.ticket_open(row.halo_id, cfg.halo_closed_status_id):
                    # A technician closed it in Halo while PCs still need the fix: open a new one next pass.
                    row.status, row.closed_at = "closed", now
                    continue
                elif row.digest != g.digest:
                    # The summary names the target version, which changes with each new release. The
                    # client goes along too, so a corrected Halo client id moves the ticket.
                    api.update_ticket(row.halo_id, {"summary": _summary(g), "details": _details(g, client, cfg.public_url),
                                                    "client_id": client.halo_client_id})
                    api.add_note(row.halo_id, f"BearWatch: the list changed. {len(g.devices)} "
                                              f"{'PC still needs' if len(g.devices) == 1 else 'PCs still need'} this fix.",
                                 cfg.halo_note_outcome)
                    row.digest = g.digest
                    touched += 1
                row.last_error, row.updated_at = None, now
            except (HaloError, httpx.HTTPError, KeyError, ValueError) as e:
                if row is not None:
                    row.last_error = str(e)[:1000]
                log.warning("halo ticket for client %s fix %s failed: %s", client.id, key, e)
        # Fixed everywhere: close.
        for key, row in rows.items():
            if row.status != "open" or key in groups:
                continue
            try:
                api.add_note(row.halo_id, "BearWatch: every PC now has this fix. Closing the ticket.", cfg.halo_note_outcome)
                api.update_ticket(row.halo_id, {"status_id": cfg.halo_closed_status_id})
                row.status, row.closed_at, row.last_error, row.updated_at = "closed", now, None, now
                touched += 1
            except (HaloError, httpx.HTTPError, KeyError, ValueError) as e:
                row.last_error = str(e)[:1000]
                log.warning("closing halo ticket %s failed: %s", row.halo_id, e)
        s.flush()
    return touched


def set_mapping(s: Session, client: Client, halo_client_id: int | None) -> None:
    """Link a client to a Halo client, or unlink it. Open tickets follow a changed id on the next
    pass (their digest is cleared so the update is sent). Unlinking stops BearWatch managing the
    open tickets; they stay in Halo as they are."""
    if halo_client_id != client.halo_client_id:
        now = utcnow()
        for row in s.scalars(select(HaloTicket).where(HaloTicket.client_id == client.id, HaloTicket.status == "open")):
            if halo_client_id is None:
                row.status, row.closed_at, row.updated_at = "closed", now, now
            else:
                row.digest = ""
    client.halo_client_id = halo_client_id


def open_count(s: Session, client_id: int) -> int:
    return s.scalar(select(func.count()).select_from(HaloTicket).where(HaloTicket.client_id == client_id, HaloTicket.status == "open")) or 0
