# BearWatch

Open-source endpoint and exposure vulnerability platform for MSPs, by Bearium Networks.

BearWatch pulls free public vulnerability data (Microsoft MSRC, NVD, CISA KEV, VulnCheck KEV,
FIRST EPSS, CISA vulnrichment, WinGet), matches it against what is installed on managed Windows
endpoints, ranks findings by real-world exploitability and groups them by the fix that closes
them.

**Status: Phase 2 in progress.** A light Windows agent (0.9 MB, about 10 MB of memory, uploads
only when something changes) reports to the server, which keeps findings with found and fixed
history and shows them on a fix-grouped dashboard behind Cloudflare Access. Every finding has a
risk score that shows how it was reached, a fix deadline, and can be covered by an exception
with a reason and an end date. Posture checks flag risky Windows settings (SMBv1, LLMNR, no
LAPS and more) from rules kept on the server. Sensor mode and PSA integration come next. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/scoring.md](docs/scoring.md),
[docs/posture.md](docs/posture.md) and [agent/README.md](agent/README.md).

## Run it locally

Needs Docker with Compose.

```bash
cp .env.example .env   # then set POSTGRES_PASSWORD and BEARWATCH_API_TOKEN
docker compose up -d --build
docker compose logs -f worker   # first full NVD sync: ~75 min (once; later runs take seconds)
```

The dashboard and API listen on `http://127.0.0.1:8080`; locally, sign in with
`BEARWATCH_API_TOKEN`. Check sync progress:

```bash
docker compose exec server bearwatch status
```

## Enroll a PC

Add a client and site on the dashboard (Clients and sites), or:

```bash
docker compose exec server bearwatch client add "Bearium Networks"
docker compose exec server bearwatch site add --client "Bearium Networks" --name "Orlando office"
```

Build the agent with `powershell -File agent\build.ps1`, then on the PC, as administrator:

```powershell
dist\bw-agent.exe enroll --server http://127.0.0.1:8080 --key bwe_...
dist\bw-agent.exe install
```

Findings appear on the dashboard about a minute after the first check-in. Production agents
must use the `https://` address of the deployed server.

## Ask it questions

Open Windows CVEs for a build and its installed KBs:

```bash
docker compose exec server bearwatch windows --build 10.0.22631.4317 --kb KB5044285
```

CVEs for an installed application, with the WinGet fix:

```bash
docker compose exec server bearwatch app --name "Google Chrome" --version 120.0.6099.71
```

Same thing over HTTP:

```bash
curl -s -H "Authorization: Bearer $BEARWATCH_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"build":"10.0.22631.4317","kbs":["KB5044285"]}' http://127.0.0.1:8080/api/match/windows
```

## Teach it new software

Add a rule to [intel/cpe_overrides.json](intel/cpe_overrides.json) mapping the program's
Windows display name to its NVD vendor and product, then check every rule has data:

```bash
docker compose exec server bearwatch overrides check
```

## Develop

```bash
cd server
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest
```

## Deploy

Production uses `compose.yaml` only: `docker compose -f compose.yaml up -d --build`. Database
migrations run automatically at startup. Before the first deploy, set up Cloudflare Access for
the dashboard and a Bypass rule for `/api/agent` (see
[Dashboard sign-in](docs/ARCHITECTURE.md#dashboard-sign-in)) and put the team domain and AUD tag
in `.env`.

The dashboard ships with Bearium's logo and fonts (Inter and Mozilla Text, SIL Open Font
License). The logo is Bearium Networks' trademark and is not covered by the GPL; other MSPs
should replace `server/bearwatch/web/static/bear-white.png` and `favicon.png` with their own.

## Credits and terms

- This product uses the NVD API but is not endorsed or certified by the NVD.
- EPSS scores are produced by FIRST (first.org/epss).
- KEV data from CISA. SSVC data from CISA vulnrichment.
- Windows fix data from the Microsoft Security Response Center CVRF API.
- The overrides file format is inspired by Fleet's cpe_translations.json (MIT).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
