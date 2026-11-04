# BearWatch architecture

BearWatch finds what is vulnerable or misconfigured on the endpoints an MSP manages, ranks it by
how likely it is to be exploited, and groups it by the fix that closes it. It is built for
Bearium Networks' own clients and released under GPL-3.0 so other MSPs can run it too.

## Pieces

```
Windows endpoints                     Client site LAN                Internet
  bw-agent (Rust service)  ----+       bw-agent --sensor mode        Cyber Scan modules + PD tools
   inventory + posture         |        (Proton engine)               scheduled per client
                               v               |                              |
                     BearWatch server (Python/FastAPI, Postgres, Docker Compose)
                       |  tenants: client > site > device                    |
                       |  intel store: MSRC, NVD, KEV, EPSS, vulnrichment,   |
                       |    WinGet, exploit signals                          |
                       |  matcher (2 paths) > scoring > findings             |
                       +--> fix-grouped dashboard, monthly PDF, HaloPSA <----+
```

| Component | Status | Notes |
|---|---|---|
| Intel store + sync worker | **Phase 0, built** | `server/bearwatch/intel/` |
| Windows OS matcher (MSRC) | **Phase 0, built** | `server/bearwatch/match/windows.py` |
| App matcher (CPE) | **Phase 0, built** | `server/bearwatch/match/apps.py` + `intel/cpe_overrides.json` |
| bw-agent (Rust) | Phase 1 | Inventory, enrollment, heartbeat. Shares a `proton-core` crate with Proton IP Scanner. |
| Findings model | Phase 1 | Dedup, fixed events, exceptions, SLAs |
| Sensor mode + unmanaged devices | Phase 2 | Proton scan engine on one agent per site |
| External monitoring | Phase 3 | Shared package extracted from Bearium Cyber Scan |
| HaloPSA + monthly PDF | Phase 3 | One ticket per fix per client |

## Two matching paths, never mixed

1. **Windows itself** is matched only from Microsoft's CVRF data. Each fix row says: this CVE,
   on this exact product, is fixed by this KB, at this build, and that KB supersedes these older
   KBs. A device is patched for a CVE when its build revision is at or past the fixed build, or
   when the KB (or any KB that supersedes it) is installed. NVD's Windows CPE data is not used.
2. **Third-party apps** are matched from NVD CPE rules. The Windows program name is mapped to a
   CPE vendor/product through `intel/cpe_overrides.json`. Unmapped programs are reported as
   unresolved rather than guessed, and get added to the overrides file.

This split is what Fleet, Vuls and WES-NG converged on. NVD alone is also no longer enough:
NIST now only fully enriches a subset of CVEs, so every source is merged server-side.

Details that matter for accuracy:

- **Build families.** Windows versions shipped as enablement packages (22H2/23H2, 21H2/22H2 on
  Windows 10, 24H2/25H2) share cumulative updates, and MSRC sometimes lists the sibling's build
  as the fixed build. The matcher compares revisions across the family.
- **Build beats KB.** When MSRC gives a comparable fixed build, the device's build decides.
  The KB and supersedence path is only used when there is no comparable build.
- **Fix grouping counts supersedence.** "Install KB X to close N" counts every open CVE that
  update would close, not only the CVEs that list KB X directly.
- **Platform-bound CPE rules.** NVD writes "Chrome on macOS" as Chrome AND macOS. Those
  platform requirements are stored per rule, and rules that need a non-Windows platform are
  skipped.
- **Unbounded wildcards are ignored for apps.** A `*` rule with no version bounds (common on
  old protocol CVEs like Logjam) would flag fully current software, so it is skipped unless a
  caller asks for it.

## Data sources

| Source | Used for | Cadence | Terms |
|---|---|---|---|
| MSRC CVRF API v3 | Windows CVE to KB, fixed build, supersedence | Daily, changed months only | Microsoft terms of use |
| NVD CVE API 2.0 | CVE records, CVSS, app CPE rules | Every 2h, incremental | Public; "uses the NVD API but is not endorsed or certified by the NVD" |
| CISA KEV | Known exploited | Every 6h | Public domain |
| VulnCheck KEV | Broader known exploited list | Every 6h, if token set | Free community account; check terms |
| FIRST EPSS | Exploit probability | Daily | Free; credit FIRST |
| CISA vulnrichment | SSVC (exploitation, automatable, impact) | On demand per CVE | CC0 |
| WinGet index | Latest version, fix command | Daily | MIT (winget-pkgs) |

## Repo layout

```
compose.yaml            production services (postgres, server, worker)
compose.override.yaml   local dev additions (ports on 127.0.0.1)
server/                 Python package `bearwatch` + tests + Dockerfile
intel/                  curated data checked into git (cpe_overrides.json)
docs/                   this file, scoring.md
agent/                  (Phase 1) Rust workspace
shared-scan/            (Phase 3) package extracted from Cyber Scan
```

## Deployment

Everything server-side is Docker Compose. Develop and test against local Docker; deploy the
final version to docker03 with `docker compose -f compose.yaml up -d` (no override file), behind
the Cloudflare Tunnel, the same way as Cyber Scan.

The repo lives on the NAS, and Docker Desktop cannot bind-mount from a mapped network drive, so
local dev has no source mounts: rebuild with `docker compose up -d --build server` after a change.
Rebuilding the worker restarts any sync in progress.

## Not done yet in Phase 0

- Schema is created with `create_all`, which never alters existing tables. Until Alembic
  arrives with the Phase 1 tables, a schema change means dropping the affected tables.
- SSVC is fetched on demand (`bearwatch ssvc CVE-...`); Phase 1 calls it for new findings.
- VulnCheck KEV code is written but untested against the live API (needs a token).
- Exploit-module signals (Nuclei templates, Metasploit) are not ingested yet.
- The refreshed offline database export for desktop Proton is not built yet.
