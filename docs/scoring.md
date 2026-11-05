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

## Risk score (built in Phase 2)

```
risk = base(tier, cvss) x importance x exposure x exception
```

- **base** places the finding by exploit tier, then by CVSS inside the tier. The bands never
  overlap, so CVSS alone can never lift a finding past a stronger exploit signal.

  | Tier | Base | Range |
  |---|---|---|
  | 1 | 90 + CVSS | 90 to 100 |
  | 2 | 70 + 1.5 x CVSS | 70 to 85 |
  | 3 | 50 + 1.5 x CVSS | 50 to 65 |
  | 4 | 4 x CVSS | 0 to 40 |

  A CVE with no CVSS from NVD or MSRC is scored as 5.0.
- **importance** is set per device on its page, 1 to 5, scaled to 0.6, 0.8, 1.0, 1.2, 1.4.
  Suggested: kiosk or lab PC 1, workstation 3, server or executive laptop 4, domain controller 5.
  Until a technician sets it, servers count as 4 and everything else as 3.
- **exposure** is 1.2 when the device is marked as reachable from the internet, else 1.0.
- **exception** is 0 for a false positive, 0.5 for a compensating control, else 1.0.

So scores run from 0 to about 168. Fixes and devices sort by their highest finding risk. Each
finding on a device page shows how its score was reached, for example
`99 base x 1.4 importance x 1.2 internet facing`. The score is recomputed after every
evaluation, when a device's settings change, and when an exception starts or ends.

This follows the Qualys TruRisk and Tenable VPR plus asset criticality split.

### Windows settings (posture checks)

A failed [posture rule](posture.md) has no CVE, so its severity stands in for the tier and CVSS.
The same formula and deadlines then apply.

| Severity | Counts as | Base | Deadline | Examples |
|---|---|---|---|---|
| Critical | tier 2, 9.0 | 83.5 | 14 days | No working antivirus, SMBv1 server on, WDigest on |
| High | tier 3, 8.0 | 62 | 30 days | Firewall off, NTLMv1 allowed, UAC off |
| Medium | tier 4, 6.0 | 24 | 90 days | LLMNR on, no LAPS |
| Low | tier 4, 3.0 | 12 | 90 days | Remote Registry starts automatically |

A critical setting ranks below a known exploited CVE and above any CVE without exploit code.

## Fix deadlines (built in Phase 2)

- Tier 1 or CVSS 9.0 and up: 14 days. CVSS 7.0 and up: 30 days. Everything else: 90 days.
- The clock starts when a finding is first found, and starts again if a fixed finding comes back.
- If the tier or CVSS changes, the deadline moves with it, counted from the same start.
- An active exception of any kind pauses the deadline. When it ends, the original deadline
  applies again, so a finding can come back already overdue.
- Overdue counts show on the overview, client and device pages. They will feed the monthly
  report in Phase 3.

## Exceptions (built in Phase 2)

An exception covers one client, optionally one device, and a fix, a CVE, or both. It also
covers matching findings that appear later.

| Reason | Score | Deadline |
|---|---|---|
| False positive | x 0 | Paused |
| Compensating control | x 0.5 | Paused |
| Risk accepted | Unchanged | Paused |
| Planned fix | Unchanged | Paused |

Every exception needs a note and an end date no more than a year out, and records who added it.
When several match one finding, the one that lowers the score most wins. Ending one early keeps
it in the list as history. The worker rescores findings within a minute of an exception expiring.
