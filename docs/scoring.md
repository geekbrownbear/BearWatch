# How BearWatch ranks findings

MSPs drown in findings sorted by CVSS. BearWatch sorts by how likely a flaw is to be used against
the client, then by impact, and always shows why a finding landed where it did.

## Exploit tier (built in Phase 0)

| Tier | Meaning | Signals |
|---|---|---|
| 1 | Known exploited | CISA KEV, VulnCheck KEV, NVD's KEV date, MSRC "Exploited:Yes", or SSVC exploitation = active |
| 2 | Public exploit code | SSVC exploitation = poc. Later: Nuclei template or Metasploit module exists |
| 3 | Likely to be exploited | EPSS score of 10% or more |
| 4 | No exploit signal | Everything else |

Within a tier, findings sort by EPSS, then CVSS. GitHub PoC repositories are a weak signal (many
are fake or malware) and will never promote a finding above tier 3 on their own.

## How the dashboard orders fixes (built in Phase 1)

Findings are grouped by the fix that closes them (one KB or one app update). Fixes sort by the
most urgent tier among their CVEs, then by how many devices need them, then by how many CVEs
they close. Each row shows its known-exploited count, top EPSS and top CVSS.

## Risk score (planned, Phase 2)

Needs per-device asset criticality, which arrives with the Phase 2 device settings.

```
risk = base(tier, cvss) x asset_criticality x exposure
```

- **base**: tier 1 starts at 90, tier 2 at 70, tier 3 at 50, tier 4 at CVSS x 4, capped at 100.
- **asset_criticality**: 1 to 5 set per device (domain controller 5, server 4, executive laptop 4,
  workstation 3, kiosk 2). Scaled to 0.6 to 1.4.
- **exposure**: 1.2 when the device or service is reachable from the internet, else 1.0.

This follows Qualys TruRisk and Tenable's VPR plus asset criticality split. Every finding stores
each factor so the dashboard can show the breakdown.

## Exceptions and SLAs (Phase 2)

- Exception reasons: false positive, compensating control, risk accepted, planned fix. Only the
  first two lower the score. Every exception has an expiry date.
- Default fix deadlines: tier 1 or critical within 14 days, high within 30, everything else 90.
  Overdue items appear in the monthly report.
