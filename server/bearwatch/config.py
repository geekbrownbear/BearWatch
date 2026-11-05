"""Settings, read from environment variables (see .env.example at the repo root)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BEARWATCH_", env_file=".env", extra="ignore")

    # postgresql+psycopg://user:pass@host/db in Compose; sqlite works for tests and quick local use.
    database_url: str = "sqlite:///./bearwatch.db"

    # Required for /api/* except /api/health. Empty means the API refuses every protected call.
    api_token: str = ""

    # Optional keys. Everything works without them, just slower (NVD) or with less coverage (VulnCheck).
    nvd_api_key: str = ""
    vulncheck_api_token: str = ""

    # How far back to pull Microsoft's monthly CVRF documents. Each is ~30 MB.
    msrc_months: int = 36

    # Where the curated software-to-CPE overrides live.
    overrides_path: Path = Path(__file__).resolve().parents[2] / "intel" / "cpe_overrides.json"
    # Windows settings checks sent to agents (docs/posture.md).
    posture_rules_path: Path = Path(__file__).resolve().parents[2] / "intel" / "posture_rules.toml"
    # Agent schedule, sent to agents on every heartbeat so it can change without a redeploy.
    heartbeat_seconds: int = 900  # 15 min: one small request
    collect_seconds: int = 14400  # 4 h: read registry, upload only if the hash changed
    inventory_refresh_days: int = 7  # force an upload this often even if nothing changed
    wua_interval_days: int = 7  # Windows Update cross-check, on sites that enable it
    sensor_interval_minutes: int = 240  # network scan by the site's sensor PC (agent 0.3.0+)

    # Dashboard sign-in. "cloudflare": trust only a valid Cloudflare Access JWT (production).
    # "token": sign in with BEARWATCH_API_TOKEN (local development).
    dashboard_auth: str = "token"
    cf_access_team_domain: str = ""  # e.g. bearium.cloudflareaccess.com
    cf_access_aud: str = ""  # the Access application's AUD tag

    # Contact string for the User-Agent we send to public feeds.
    user_agent: str = "BearWatch/0.1 (+https://github.com/geekbrownbear/BearWatch)"


@lru_cache
def get_settings() -> Settings:
    return Settings()
