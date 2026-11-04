"""Dashboard sign-in.

Production (BEARWATCH_DASHBOARD_AUTH=cloudflare): the dashboard hostname sits behind a
Cloudflare Access application. Cloudflare adds a signed JWT to every request; we verify its
signature against the team's public keys, its audience (the application's AUD tag) and its
issuer, and use the email claim as the technician's identity. Requests without a valid token
are refused even if they somehow reach the server without passing through Access.

Local development (BEARWATCH_DASHBOARD_AUTH=token): sign in once with BEARWATCH_API_TOKEN.
The cookie holds an HMAC of the token, not the token itself.

Every state-changing form post must come from the dashboard's own origin (CSRF protection
that works with both modes, since the Access cookie is sent on cross-site requests too).
"""

import hashlib
import hmac
from functools import lru_cache
from urllib.parse import urlsplit

import jwt
from fastapi import HTTPException, Request

from .config import get_settings

COOKIE = "bw_session"


class NotSignedIn(Exception):
    """Raised in token mode so the app can redirect to the sign-in page."""


@lru_cache(maxsize=4)
def _jwks(team_domain: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"https://{team_domain}/cdn-cgi/access/certs", cache_keys=True, lifespan=3600)


def session_value(api_token: str) -> str:
    return hmac.new(api_token.encode(), b"bearwatch-dashboard", hashlib.sha256).hexdigest()


def _cloudflare_user(request: Request) -> str:
    cfg = get_settings()
    team, aud = cfg.cf_access_team_domain.strip(), cfg.cf_access_aud.strip()
    if not team or not aud:
        raise HTTPException(500, "Cloudflare Access is not configured (BEARWATCH_CF_ACCESS_TEAM_DOMAIN, BEARWATCH_CF_ACCESS_AUD)")
    token = request.headers.get("cf-access-jwt-assertion") or request.cookies.get("CF_Authorization")
    if not token:
        raise HTTPException(403, "Sign in through Cloudflare Access")
    try:
        key = _jwks(team).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], audience=aud, issuer=f"https://{team}")
    except jwt.PyJWTError as e:
        raise HTTPException(403, "Cloudflare Access token is not valid") from e
    return claims.get("email") or claims.get("common_name") or "service token"


def current_user(request: Request) -> str:
    cfg = get_settings()
    if cfg.dashboard_auth == "cloudflare":
        return _cloudflare_user(request)
    if cfg.dashboard_auth != "token":
        raise HTTPException(500, f"unknown BEARWATCH_DASHBOARD_AUTH {cfg.dashboard_auth!r}")
    supplied = request.cookies.get(COOKIE, "")
    if cfg.api_token and hmac.compare_digest(supplied, session_value(cfg.api_token)):
        return "local admin"
    raise NotSignedIn


def check_origin(request: Request) -> None:
    """Refuse form posts whose Origin (or Referer) is not this site."""
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    if urlsplit(source).netloc.lower() != request.url.netloc.lower():
        raise HTTPException(403, "cross-site request refused")
