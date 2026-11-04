"""Intel store schema.

One table per kind of fact, keyed so every sync is an idempotent upsert. Nothing here is
client data yet; tenants, devices and findings arrive in Phase 1.
"""

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, Index, Integer, String, Text
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

    __table_args__ = (Index("ix_cpe_match_vendor_product", "vendor", "product"),)


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
