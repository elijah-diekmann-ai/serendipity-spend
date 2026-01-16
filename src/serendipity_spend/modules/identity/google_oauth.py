from __future__ import annotations

import time
import urllib.parse
from typing import Any

import httpx
from jose import jwk, jwt

from serendipity_spend.core.config import settings

_GOOGLE_OIDC_CONFIG_URL = "https://accounts.google.com/.well-known/openid-configuration"
_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}

_oidc_config: dict[str, Any] | None = None
_oidc_config_expires_at: float = 0.0
_jwks: dict[str, Any] | None = None
_jwks_expires_at: float = 0.0


def google_oauth_enabled() -> bool:
    return bool(settings.google_oauth_client_id and settings.google_oauth_client_secret)


def build_google_authorize_url(*, state: str, redirect_uri: str) -> str:
    if not google_oauth_enabled():
        raise RuntimeError("Google OAuth is not configured")

    params: dict[str, str] = {
        "client_id": settings.google_oauth_client_id or "",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
        "include_granted_scopes": "true",
    }
    if settings.google_oauth_allowed_domain:
        params["hd"] = settings.google_oauth_allowed_domain
    return f"{_GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"


def exchange_google_code(*, code: str, redirect_uri: str) -> dict[str, Any]:
    if not google_oauth_enabled():
        raise RuntimeError("Google OAuth is not configured")

    data = {
        "code": code,
        "client_id": settings.google_oauth_client_id,
        "client_secret": settings.google_oauth_client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(_GOOGLE_TOKEN_URL, data=data)
    try:
        payload = resp.json()
    except Exception as e:  # noqa: BLE001
        raise ValueError("Google token exchange failed") from e
    if resp.status_code >= 400:
        raise ValueError(f"Google token exchange failed: {payload}")
    return payload


def verify_google_id_token(id_token: str) -> dict[str, Any]:
    if not settings.google_oauth_client_id:
        raise RuntimeError("Google OAuth is not configured")

    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header.get("kid")
    alg = unverified_header.get("alg") or "RS256"
    if not kid:
        raise ValueError("Invalid Google ID token (missing kid)")

    oidc_config = _get_google_oidc_config()
    jwks_uri = oidc_config.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise ValueError("Invalid Google OIDC configuration (missing jwks_uri)")

    jwks_data = _get_google_jwks(jwks_uri)
    key_data = _find_jwk_by_kid(jwks_data, kid)
    if key_data is None:
        # Refresh once in case Google rotated signing keys.
        jwks_data = _fetch_google_jwks(jwks_uri)
        key_data = _find_jwk_by_kid(jwks_data, kid)
    if key_data is None:
        raise ValueError("Invalid Google ID token (unknown kid)")

    key = jwk.construct(key_data, alg)
    claims = jwt.decode(
        id_token,
        key.to_pem().decode("utf-8"),
        algorithms=[alg],
        audience=settings.google_oauth_client_id,
        options={"verify_iss": False},
    )

    issuer = claims.get("iss")
    if issuer not in _GOOGLE_ISSUERS:
        raise ValueError("Invalid Google ID token issuer")

    email = claims.get("email")
    email_verified = claims.get("email_verified")
    if not isinstance(email, str) or not email:
        raise ValueError("Google ID token missing email")
    if email_verified is not True:
        raise ValueError("Google account email is not verified")

    allowed_domain = (settings.google_oauth_allowed_domain or "").strip().lower()
    if allowed_domain:
        if not email.lower().endswith(f"@{allowed_domain}"):
            raise ValueError("Email domain not allowed")
        hosted_domain = claims.get("hd")
        if isinstance(hosted_domain, str) and hosted_domain.lower() != allowed_domain:
            raise ValueError("Hosted domain not allowed")

    return claims


def _get_google_oidc_config() -> dict[str, Any]:
    global _oidc_config, _oidc_config_expires_at  # noqa: PLW0603
    now = time.time()
    if _oidc_config and now < _oidc_config_expires_at:
        return _oidc_config

    with httpx.Client(timeout=10.0) as client:
        resp = client.get(_GOOGLE_OIDC_CONFIG_URL)
    resp.raise_for_status()
    _oidc_config = resp.json()
    _oidc_config_expires_at = now + _ttl_from_cache_headers(resp.headers, default_seconds=3600)
    return _oidc_config


def _get_google_jwks(jwks_uri: str) -> dict[str, Any]:
    global _jwks, _jwks_expires_at  # noqa: PLW0603
    now = time.time()
    if _jwks and now < _jwks_expires_at:
        return _jwks
    return _fetch_google_jwks(jwks_uri)


def _fetch_google_jwks(jwks_uri: str) -> dict[str, Any]:
    global _jwks, _jwks_expires_at  # noqa: PLW0603
    now = time.time()
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(jwks_uri)
    resp.raise_for_status()
    _jwks = resp.json()
    _jwks_expires_at = now + _ttl_from_cache_headers(resp.headers, default_seconds=3600)
    return _jwks


def _ttl_from_cache_headers(headers: httpx.Headers, *, default_seconds: int) -> int:
    cache_control = headers.get("cache-control") or ""
    for part in cache_control.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except Exception:
                return default_seconds
    return default_seconds


def _find_jwk_by_kid(jwks_data: dict[str, Any], kid: str) -> dict[str, Any] | None:
    keys = jwks_data.get("keys")
    if not isinstance(keys, list):
        return None
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == kid:
            return key
    return None

