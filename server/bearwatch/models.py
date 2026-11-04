"""Database schema.

Intel store: one table per kind of fact, keyed so every sync is an idempotent upsert.
Tenants and endpoints (Phase 1): client > site > device, the device's last inventory, and
findings with found/fixed events. Schema changes go through Alembic (bearwatch/migrations).
"""

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Cve(Base):
    """Core CVE record from NVD."""

    __tablename__ = "cve"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str | None] = mapped_column(String(16))
    # NVD copies the CISA KEV date onto the CVE; kept as a fallback if the KEV feed is stale.
    nvd_kev_added: Mapped[date | None] = mapped_column(Date)


class CpeMatch(Base):
    """A vulnerable-software rule from an NVD CVE configuration, flattened."""

    __tablename__ = "cpe_match"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    criteria: Mapped[str] = mapped_column(String(400))
    part: Mapped[str] = mapped_column(String(1))
    vendor: Mapped[str] = mapped_column(String(120))
    product: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(120))
    target_sw: Mapped[str] = mapped_column(String(80))
    version_start_incl: Mapped[str | None] = mapped_column(String(120))
    version_start_excl: Mapped[str | None] = mapped_column(String(120))
    version_end_incl: Mapped[str | None] = mapped_column(String(120))
    version_end_excl: Mapped[str | None] = mapped_column(String(120))
    # "vendor:product" of the platforms this rule needs (NVD AND configurations, e.g. Chrome
    # running on macOS). Empty means any platform.
    platforms: Mapped[list] = mapped_column(JSON, default=list)

    __table_args__ = (
        Index("ix_cpe_match_vendor_product", "vendor", "product"),
        # The app matcher's fallback looks programs up by product name alone.
        Index("ix_cpe_match_product", "product"),
    )


class Kev(Base):
    """Known-exploited listing. source is 'cisa' or 'vulncheck'."""

    __tablename__ = "kev"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(200))
    product: Mapped[str | None] = mapped_column(String(200))
    name: Mapped[str | None] = mapped_column(String(400))
    date_added: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False)


class Epss(Base):
    __tablename__ = "epss"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    score_date: Mapped[date | None] = mapped_column(Date)


class Ssvc(Base):
    """CISA ADP (vulnrichment) SSVC decision points, fetched on demand per CVE."""

    __tablename__ = "ssvc"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    found: Mapped[bool] = mapped_column(Boolean, default=False)
    exploitation: Mapped[str | None] = mapped_column(String(16))
    automatable: Mapped[str | None] = mapped_column(String(8))
    technical_impact: Mapped[str | None] = mapped_column(String(16))
    fetched_at: Mapped[datetime] = mapped_column(DateTime)


class MsrcDocument(Base):
    """One monthly MSRC CVRF document; current_release lets us skip unchanged months."""

    __tablename__ = "msrc_document"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    title: Mapped[str | None] = mapped_column(String(200))
    initial_release: Mapped[datetime | None] = mapped_column(DateTime)
    current_release: Mapped[datetime | None] = mapped_column(DateTime)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime)


class MsrcProduct(Base):
    __tablename__ = "msrc_product"
    product_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(400), index=True)
    cpe: Mapped[str | None] = mapped_column(String(400))


class MsrcVuln(Base):
    """Per-CVE facts from MSRC (title, exploitation flags)."""

    __tablename__ = "msrc_vuln"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    doc_id: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str | None] = mapped_column(String(400))
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    publicly_disclosed: Mapped[bool] = mapped_column(Boolean, default=False)


class MsrcFix(Base):
    """A vendor fix (Remediation Type 2) for one CVE on one product.

    kb is the KB number without the 'KB' prefix when numeric. supersedes holds the KB numbers
    this update replaces, which is how an installed newer cumulative update proves an older
    fix is present.
    """

    __tablename__ = "msrc_fix"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    doc_id: Mapped[str] = mapped_column(String(16), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    product_id: Mapped[str] = mapped_column(String(32), index=True)
    kb: Mapped[str | None] = mapped_column(String(64), index=True)
    fixed_build: Mapped[str | None] = mapped_column(String(64))
    supersedes: Mapped[list] = mapped_column(JSON, default=list)
    subtype: Mapped[str | None] = mapped_column(String(64))
    url: Mapped[str | None] = mapped_column(String(400))
    severity: Mapped[str | None] = mapped_column(String(16))
    impact: Mapped[str | None] = mapped_column(String(64))
    cvss_score: Mapped[float | None] = mapped_column(Float)


class WingetPackage(Base):
    """Latest known version per WinGet package, plus the names/publishers/product codes used to find it."""

    __tablename__ = "winget_package"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(String(400))
    latest_version: Mapped[str | None] = mapped_column(String(120))
    norm_names: Mapped[list] = mapped_column(JSON, default=list)
    norm_publishers: Mapped[list] = mapped_column(JSON, default=list)
    product_codes: Mapped[list] = mapped_column(JSON, default=list)


class SyncState(Base):
    """Last run per source. cursor holds source-specific progress (e.g. NVD lastModified high-water mark)."""

    __tablename__ = "sync_state"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_started: Mapped[datetime | None] = mapped_column(DateTime)
    last_success: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error: Mapped[str | None] = mapped_column(Text)
    rows: Mapped[int | None] = mapped_column(Integer)
    cursor: Mapped[str | None] = mapped_column(String(64))


# --- Tenants and endpoints (Phase 1) -------------------------------------------------------


class Client(Base):
    __tablename__ = "client"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Site(Base):
    """A client location. Agents enroll with the site's key; only its SHA-256 is stored."""

    __tablename__ = "site"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("client.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    enroll_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enroll_key_hint: Mapped[str] = mapped_column(String(12))
    # The Windows Update cross-check makes the PC's update service work for a minute or more,
    # so it is opt-in per site and runs weekly at most, when the PC is idle and on AC power.
    wua_check: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    __table_args__ = (UniqueConstraint("client_id", "name"),)


class Device(Base):
    __tablename__ = "device"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("site.id", ondelete="CASCADE"), index=True)
    machine_guid: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(255))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    os_caption: Mapped[str | None] = mapped_column(String(200))
    os_build: Mapped[str | None] = mapped_column(String(32))
    os_arch: Mapped[str | None] = mapped_column(String(8))
    is_server: Mapped[bool] = mapped_column(Boolean, default=False)
    server_core: Mapped[bool] = mapped_column(Boolean, default=False)
    os_product: Mapped[str | None] = mapped_column(String(200))  # MSRC product name, None if unknown build
    # An update is installed but waits for a restart; the running build is still the old one.
    reboot_pending: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    # KB numbers (digits only) installed but waiting for that restart. Agents before 0.1.1 omit them.
    pending_kbs: Mapped[list | None] = mapped_column(JSON)
    inventory_hash: Mapped[str | None] = mapped_column(String(64))
    enrolled_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_inventory_at: Mapped[datetime | None] = mapped_column(DateTime)
    # Set by inventory uploads and intel syncs; the worker re-evaluates findings when true.
    needs_match: Mapped[bool] = mapped_column(Boolean, default=False)
    last_match_at: Mapped[datetime | None] = mapped_column(DateTime)
    match_error: Mapped[str | None] = mapped_column(Text)
    rescan_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    wua_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    wua_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (UniqueConstraint("site_id", "machine_guid"),)


class DeviceSoftware(Base):
    """One installed program from the last inventory, with how it resolved to NVD data."""

    __tablename__ = "device_software"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(400))
    version: Mapped[str] = mapped_column(String(120))
    publisher: Mapped[str | None] = mapped_column(String(200))
    scope: Mapped[str] = mapped_column(String(8), default="machine")  # machine | user
    resolved_by: Mapped[str | None] = mapped_column(String(12))  # override | heuristic | unresolved
    cpe: Mapped[list] = mapped_column(JSON, default=list)
    winget_id: Mapped[str | None] = mapped_column(String(200))
    latest_version: Mapped[str | None] = mapped_column(String(120))


class DeviceKb(Base):
    __tablename__ = "device_kb"
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"), primary_key=True)
    kb: Mapped[str] = mapped_column(String(16), primary_key=True)


class WuaUpdate(Base):
    """An update Windows Update itself reports as missing (the cross-check)."""

    __tablename__ = "wua_update"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"), index=True)
    kb: Mapped[str | None] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(400))
    severity: Mapped[str | None] = mapped_column(String(16))
    is_security: Mapped[bool] = mapped_column(Boolean, default=False)
    cves: Mapped[list] = mapped_column(JSON, default=list)


class Finding(Base):
    """One CVE on one thing on one device. Rows are never deleted; status moves open <-> fixed.

    subject_key is stable across upgrades ("windows", or the normalized program name without
    its version), so updating 7-Zip closes the old finding instead of orphaning it.
    """

    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(8))  # os | app
    subject_key: Mapped[str] = mapped_column(String(200))
    subject: Mapped[str] = mapped_column(String(400))
    subject_version: Mapped[str | None] = mapped_column(String(200))
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    fix_key: Mapped[str] = mapped_column(String(220), index=True)  # kb:5044285 | winget:Google.Chrome | app:<subject_key>
    fix_label: Mapped[str] = mapped_column(String(400))
    status: Mapped[str] = mapped_column(String(8), default="open", index=True)
    exploit_tier: Mapped[int] = mapped_column(Integer, default=4)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    epss: Mapped[float | None] = mapped_column(Float)
    cvss: Mapped[float | None] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime)

    __table_args__ = (UniqueConstraint("device_id", "source", "subject_key", "cve_id"),)


class FindingEvent(Base):
    """found / fixed / reopened, so reports can show progress and not just backlog."""

    __tablename__ = "finding_event"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    event: Mapped[str] = mapped_column(String(10))
    at: Mapped[datetime] = mapped_column(DateTime, index=True)
