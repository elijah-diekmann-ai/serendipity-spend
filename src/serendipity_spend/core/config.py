from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "dev"
    base_url: str = "http://localhost:8000"
    secret_key: str = "change-me"

    database_url: str = "sqlite:///./serendipity.db"
    redis_url: str = "redis://localhost:6379/0"

    google_oauth_client_id: str | None = None
    google_oauth_client_secret: str | None = None
    google_oauth_allowed_domain: str | None = "serendipitycapital.com"

    storage_backend: Literal["local", "s3"] = "local"
    local_storage_path: Path = Path(".local_storage")

    s3_endpoint_url: str | None = None
    s3_region: str | None = None
    s3_bucket: str = "serendipity-spend"
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None

    init_admin_email: str | None = None
    init_admin_password: str | None = None

    access_token_exp_minutes: int = 60 * 24


settings = Settings()
