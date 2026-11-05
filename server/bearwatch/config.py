"""Settings, read from environment variables (see .env.example at the repo root)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Compose passes an unset variable as "" (BEARWATCH_HALO_TICKET_TYPE_ID=); treat that as unset.
    model_config = SettingsConfigDict(env_prefix="BEARWATCH_", env_file=".env", extra="ignore", env_ignore_empty=True)

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
    lifecycle_path: Path = Path(__file__).resolve().parents[2] / "intel" / "windows_lifecycle.toml"
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
    # The dashboard's address as technicians reach it, for links in Halo tickets. Optional.
    public_url: str = ""

    # HaloPSA tickets (docs/halo.md). Off until url, client id and secret are set; dry run until
    # halo_dry_run is false. The secret comes from the environment, never the repo.
    halo_url: str = ""  # https://bearium.halopsa.com
    halo_tenant: str = ""  # hosted Halo only
    halo_client_id: str = ""
    halo_client_secret: str = ""
    halo_dry_run: bool = True
    halo_ticket_type_id: int | None = None  # None: Halo's default ticket type
    halo_closed_status_id: int = 9
    halo_note_outcome: str = "Private Note"
    halo_min_risk: float = 50.0  # plus every known exploited or overdue fix

    # Contact string for the User-Agent we send to public feeds.
    user_agent: str = "BearWatch/0.1 (+https://github.com/geekbrownbear/BearWatch)"


@lru_cache
def get_settings() -> Settings:
    return Settings()
