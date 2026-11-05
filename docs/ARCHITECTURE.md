# BearWatch architecture

BearWatch finds what is vulnerable or misconfigured on the endpoints an MSP manages, ranks it by
how likely it is to be exploited, and groups it by the fix that closes it. It is built for
Bearium Networks' own clients and released under GPL-3.0 so other MSPs can run it too.

## Pieces

```
Windows endpoints                     Client site LAN                Internet
  bw-agent (Rust service)  ----+       bw-agent --sensor mode        Cyber Scan modules + PD tools
   inventory, 0.9 MB exe       |        (Proton engine)               scheduled per client
                               v               |                              |
                     BearWatch server (Python/FastAPI, Postgres, Docker Compose)
                       |  tenants: client > site > device                    |
                       |  intel store: MSRC, NVD, KEV x2, EPSS, vulnrichment,|
                       |    WinGet                                           |
                       |  matcher (2 paths) + posture rules > findings >     |
                       |    risk, deadlines, exceptions                      |
                       +--> fix-grouped dashboard, monthly PDF, HaloPSA <----+
```

| Component | Status | Where |
|---|---|---|
| Intel store + sync worker | Phase 0, built | `server/bearwatch/intel/` |
| Windows OS matcher (MSRC) | Phase 0, built | `server/bearwatch/match/windows.py` |
| App matcher (CPE) | Phase 0, built | `server/bearwatch/match/apps.py` + `intel/cpe_overrides.json` |
| Tenants, enrollment, agent API | **Phase 1, built** | `server/bearwatch/tenants.py`, `agent_api.py`, `inventory.py` |
| Findings with found/fixed/reopened events | **Phase 1, built** | `server/bearwatch/findings.py` |
| Fix-grouped dashboard, Cloudflare Access sign-in | **Phase 1, built** | `server/bearwatch/web/`, `auth.py` |
| bw-agent (Rust, Windows service) | **Phase 1, built** | `agent/` |
| Schema migrations (Alembic) | **Phase 1, built** | `server/bearwatch/migrations/` |
| Risk score, fix deadlines, exceptions | **Phase 2, built** | `server/bearwatch/scoring.py`, [scoring.md](scoring.md) |
| Posture checks (Windows settings) | **Phase 2, built** | `server/bearwatch/posture.py`, `intel/posture_rules.toml`, `agent/src/posture.rs`, [posture.md](posture.md) |
| Sensor mode, unmanaged devices, network issues | **Phase 2, built** | `server/bearwatch/sensor.py`, `agent/src/sensor/`, [sensor.md](sensor.md) |
| Monthly client report (PDF), Windows support dates | **Phase 3, built** | `server/bearwatch/report.py`, `lifecycle.py`, `intel/windows_lifecycle.toml`, [report.md](report.md) |
| HaloPSA tickets (one per fix per client, auto-closed) | **Phase 3, built** | `server/bearwatch/halo.py`, [halo.md](halo.md) |
| External exposure (Shodan InternetDB, SPF, DMARC, DNSSEC, certificates), no scanning | **Phase 3, built** | `server/bearwatch/external.py`, [external.md](external.md) |
| Active external scanning (nuclei, port sweeps) | Later: needs client permission | |

## Two matching paths, never mixed

1. **Windows itself** is matched only from Microsoft's CVRF data. Each fix row says: this CVE,
   on this exact product, is fixed by this KB, at this build, and that KB supersedes these older
   KBs. A device is patched for a CVE when its build revision is at or past the fixed build, or
   when the KB (or any KB that supersedes it) is installed. NVD's Windows CPE data is not used.
2. **Third-party apps** are matched from NVD CPE rules. The Windows program name is mapped to a
   CPE vendor/product through `intel/cpe_overrides.json`. Unmapped programs are listed on the
   dashboard's Unmapped software page rather than guessed, and get added to the overrides file.

This split is what Fleet, Vuls and WES-NG converged on. NVD alone is also no longer enough:
NIST now only fully enriches a subset of CVEs, so every source is merged server-side.

Details that matter for accuracy:

- **Build families.** Windows versions shipped as enablement packages (22H2/23H2, 21H2/22H2 on
  Windows 10, 24H2/25H2) share cumulative updates, and MSRC sometimes lists the sibling's build
  as the fixed build. The matcher compares revisions across the family.
- **Build beats KB.** When MSRC gives a comparable fixed build, the device's running build
  decides. This matters: an update waiting for a restart already shows in `Get-HotFix` (and in
  most KB-list tools) as installed, but the PC is still running the old build and is still
  exposed. BearWatch reports those CVEs as open. The agent also sends the KBs that servicing
  lists as installed but waiting for a restart (CBS state 0x60), and only a fix in that list is
  labeled "a restart is pending". Other open fixes on the same PC still say "Install".
- **No OS data is not a fix.** When a build cannot be mapped to an MSRC product, or MSRC rows
  for it are missing, OS matching is skipped and existing Windows findings stay open. The
  device page shows why in its match error.
- **Fix grouping counts supersedence.** "Install KB X" closes every open CVE that update would
  close, not only the CVEs that list KB X directly.
- **Platform-bound CPE rules.** NVD writes "Chrome on macOS" as Chrome AND macOS. Those
  platform requirements are stored per rule, and rules that need a non-Windows platform are
  skipped.
- **Unbounded wildcards are ignored for apps.** A `*` rule with no version bounds (common on
  old protocol CVEs like Logjam) would flag fully current software, so it is skipped.
- **Only curated mappings produce findings.** The name-based fallback is shown as a suggestion
  only. On the first real PC it proposed Mattermost's Google Drive plugin for Google Drive and a
  Jenkins plugin for Microsoft Log Parser; counting those would put false CVEs in front of a
  client.

## The agent: light by design

The agent collects; the server does every expensive step. Measured on a 438-program
Windows 11 25H2 workstation:

| | Target | Measured |
|---|---|---|
| Exe size | a few MB | 0.88 MB |
| Inventory pass (registry read, hash) | under 1 s CPU | 57 ms wall, 78 ms CPU |
| Peak memory | under 15 MB | 9.2 MB |
| Upload | under 50 KB | 9 KB gzip (47 KB JSON), only when something changed |

How it stays out of the way:

- **No WMI, PowerShell, file system walk or driver.** Everything comes from the registry:
  `Windows NT\CurrentVersion` (build and UBR), Component Based Servicing packages in state
  Installed (KBs), and the Uninstall keys (64-bit, 32-bit, and each signed-in user's hive).
  Posture checks add about 30 settings values from policy and security keys, plus antivirus
  health from one Windows Security Center call. The server picks which values; the agent
  limits what it will read and sends numbers only (see [posture.md](posture.md)).
- **Asleep almost all the time.** A heartbeat every 15 minutes carries the hash of the last
  inventory. The registry is re-read every 4 hours, and the inventory is uploaded only when the
  hash changed (or once a week as a refresh). Intervals come from the server, with 10% jitter.
- **Background mode.** Collection runs with `THREAD_MODE_BACKGROUND_BEGIN`: lowest CPU, I/O
  and memory priority.
- **Windows Update cross-check is opt-in per site**, weekly at most, and only when the PC is on
  AC power with system CPU under 20%. It is the one step that makes Windows work for a minute.
- **Delayed auto-start service** running as LocalSystem, restarted by Windows after a crash.

Known gaps: per-user installs of users who are signed out are not read (loading their registry
hives would be intrusive), and .NET Framework updates are not matched yet (they are MSRC add-on
products and need the KB list from WMI or servicing session data).

## Agent protocol and security

| Call | Auth | Purpose |
|---|---|---|
| `POST /api/agent/enroll` | site enrollment key | MachineGuid + hostname in, device token out. Same MachineGuid in the same site keeps the device and its history, and revokes the old token. |
| `POST /api/agent/heartbeat` | device token | Returns whether to upload, collect now (rescan button), or run the Windows Update check. |
| `POST /api/agent/inventory` | device token | Gzip JSON, 8 MB decompressed cap, schema-validated. Stored, then matched by the worker within 30 s. |
| `POST /api/agent/posture` | device token | The settings values the posture rules read. Fetched only when the heartbeat's posture hash changes. |
| `POST /api/agent/sensor` | device token, gzip | A network scan from the site's sensor PC (agent 0.3.0+). Any other PC gets 409. See [sensor.md](sensor.md). |

- Enrollment keys and device tokens are 32 random bytes; the server stores only SHA-256.
- The agent requires `https://` (plain http only for localhost) and uses Windows' own TLS stack
  and certificate store.
- Its config folder, `%ProgramData%\BearWatch`, is restricted to SYSTEM and Administrators.

## Dashboard sign-in

Production runs with `BEARWATCH_DASHBOARD_AUTH=cloudflare`. Set up on Cloudflare Zero Trust:

1. An Access application for the BearWatch hostname, policy: Bearium staff (Microsoft 365).
2. A second, more specific Access application for the same hostname with path `/api/agent`,
   policy action **Bypass**, so agents at client sites can reach their three endpoints.
3. Put the team domain and the first application's AUD tag in `.env`
   (`BEARWATCH_CF_ACCESS_TEAM_DOMAIN`, `BEARWATCH_CF_ACCESS_AUD`).

BearWatch verifies the Access JWT itself (signature, audience, issuer, expiry), so a request
that reaches the container without passing through Access is still refused. Every form post must
come from the dashboard's own origin. Pages send a strict Content-Security-Policy and run no
JavaScript.

Local development (`compose.override.yaml`) uses `token` mode: sign in with
`BEARWATCH_API_TOKEN`.

## Data sources

| Source | Used for | Cadence | Terms |
|---|---|---|---|
| MSRC CVRF API v3 | Windows CVE to KB, fixed build, supersedence | Daily, changed months only | Microsoft terms of use |
| NVD CVE API 2.0 | CVE records, CVSS, app CPE rules | Every 2h, incremental | Public; "uses the NVD API but is not endorsed or certified by the NVD" |
| CISA KEV | Known exploited | Every 6h | Public domain |
| VulnCheck KEV | Broader known exploited list (about 4,000 CVEs beyond CISA's) | Every 6h, if token set | Free community account; check terms |
| FIRST EPSS | Exploit probability | Daily | Free; credit FIRST |
| CISA vulnrichment | SSVC (exploitation, automatable, impact) | On demand per CVE | CC0 |
| WinGet index | Latest version, fix command | Daily | MIT (winget-pkgs) |

After any feed sync succeeds, every device is queued for re-evaluation, so a new KEV listing
or CVE reaches findings without waiting for an agent.

## Repo layout

```
compose.yaml            production services (postgres, server, worker) + agent-build tool
compose.override.yaml   local dev additions (ports on 127.0.0.1, token sign-in)
server/                 Python package `bearwatch` + tests + Dockerfile
  bearwatch/migrations/ Alembic revisions, applied automatically at startup
  bearwatch/web/        dashboard templates and static files
agent/                  Rust agent, Dockerfile (cross-compile), build.ps1
intel/                  curated data checked into git (cpe_overrides.json, posture_rules.toml, windows_lifecycle.toml)
docs/                   this file, scoring.md, posture.md, sensor.md, report.md, halo.md, external.md
shared-scan/            (Phase 3) package extracted from Cyber Scan
```

## Deployment

Everything server-side is Docker Compose. Develop and test against local Docker; deploy the
final version to docker03 with `docker compose -f compose.yaml up -d` (no override file), behind
the Cloudflare Tunnel, the same way as Cyber Scan.

The repo lives on the NAS, and Docker Desktop cannot bind-mount from a mapped network drive, so
local dev has no source mounts: rebuild with `docker compose up -d --build server worker` after
a change. Rebuilding the worker restarts any sync in progress.

Schema changes are Alembic revisions in `server/bearwatch/migrations/versions`. Every process
runs `upgrade head` at startup under a Postgres advisory lock. Databases created before Alembic
(Phase 0) are stamped at revision 0001 automatically.

## Not done yet

- .NET Framework and other MSRC add-on products (needs a fuller KB list).
- Per-user installs of signed-out users.
- SSVC is fetched on demand (`bearwatch ssvc CVE-...`), not yet for every new finding.
- Exploit-module signals (Nuclei templates, Metasploit) are not ingested yet.
- Code signing and an MSI for the agent.
- The refreshed offline database export for desktop Proton.
- Network issues have no fix deadlines or exceptions yet, and are not in the risk score.
- Sensor scans IPv4 only.
