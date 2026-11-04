"""Attach exploitability context (CVSS, KEV, EPSS, SSVC) to a set of CVE ids, and rank them."""

from dataclasses import asdict, dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Cve, Epss, Kev, MsrcVuln, Ssvc


@dataclass
class CveContext:
    cve_id: str
    cvss: float | None = None
    severity: str | None = None
    kev: list[str] = field(default_factory=list)  # sources: cisa, vulncheck, nvd
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    exploited_per_msrc: bool = False
    ssvc_exploitation: str | None = None
    exploit_tier: int = 4
    description: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def exploit_tier(c: CveContext) -> int:
    """1 = known exploited, 2 = active/PoC per SSVC, 3 = EPSS >= 10%, 4 = no exploit signal.

    Nuclei template / Metasploit module signals slot in at tier 2 once that feed lands.
    See docs/scoring.md.
    """
    if c.kev or c.exploited_per_msrc or c.ssvc_exploitation == "active":
        return 1
    if c.ssvc_exploitation == "poc":
        return 2
    if (c.epss or 0) >= 0.10:
        return 3
    return 4


def enrich(session: Session, cve_ids: list[str]) -> dict[str, CveContext]:
    ids = sorted({c.upper() for c in cve_ids})
    out = {i: CveContext(cve_id=i) for i in ids}
    if not ids:
        return out
    for chunk_start in range(0, len(ids), 500):
        chunk = ids[chunk_start : chunk_start + 500]
        for c in session.scalars(select(Cve).where(Cve.id.in_(chunk))):
            ctx = out[c.id]
            ctx.cvss, ctx.severity, ctx.description = c.cvss_score, c.severity, c.description
            if c.nvd_kev_added:
                ctx.kev.append("nvd")
        for k in session.scalars(select(Kev).where(Kev.cve_id.in_(chunk))):
            out[k.cve_id].kev.append(k.source)
            out[k.cve_id].kev_ransomware |= bool(k.ransomware)
        for e in session.scalars(select(Epss).where(Epss.cve_id.in_(chunk))):
            out[e.cve_id].epss, out[e.cve_id].epss_percentile = e.score, e.percentile
        for m in session.scalars(select(MsrcVuln).where(MsrcVuln.cve_id.in_(chunk))):
            out[m.cve_id].exploited_per_msrc = m.exploited
        for s in session.scalars(select(Ssvc).where(Ssvc.cve_id.in_(chunk))):
            out[s.cve_id].ssvc_exploitation = s.exploitation
    for ctx in out.values():
        ctx.kev = sorted(set(ctx.kev))
        ctx.exploit_tier = exploit_tier(ctx)
    return out


def rank_key(ctx: CveContext) -> tuple:
    """Sort order: exploit tier, then EPSS, then CVSS (all descending in urgency)."""
    return (ctx.exploit_tier, -(ctx.epss or 0), -(ctx.cvss or 0), ctx.cve_id)
