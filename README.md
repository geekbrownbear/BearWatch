# BearWatch

Open-source endpoint and exposure vulnerability platform for MSPs, by Bearium Networks.

BearWatch pulls free public vulnerability data (Microsoft MSRC, NVD, CISA KEV, FIRST EPSS, CISA
vulnrichment, WinGet), matches it against what is installed on managed Windows endpoints, ranks
findings by real-world exploitability and groups them by the fix that closes them.

**Status: Phase 0.** The intel store, sync worker and both matchers work. The Windows agent,
dashboard and PSA integration come next. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/scoring.md](docs/scoring.md).

## Run it locally

Needs Docker with Compose.

```bash
cp .env.example .env   # then set POSTGRES_PASSWORD and BEARWATCH_API_TOKEN
docker compose up -d --build
docker compose logs -f worker   # first full NVD sync: ~75 min (once; later runs take seconds)
```

The API listens on `http://127.0.0.1:8080`. Check sync progress:

```bash
docker compose exec server bearwatch status
```

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

Production uses `compose.yaml` only: `docker compose -f compose.yaml up -d --build`.

## Credits and terms

- This product uses the NVD API but is not endorsed or certified by the NVD.
- EPSS scores are produced by FIRST (first.org/epss).
- KEV data from CISA. SSVC data from CISA vulnrichment.
- Windows fix data from the Microsoft Security Response Center CVRF API.
- The overrides file format is inspired by Fleet's cpe_translations.json (MIT).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
