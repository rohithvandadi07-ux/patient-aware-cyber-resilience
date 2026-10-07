"""Application settings, loaded from environment variables.

Nothing in this codebase hardcodes a host, port, secret, or environment-specific
path. Every configurable value is declared here with an explicit default (safe for
local development only) and is expected to be overridden via environment variables
or a `.env` file in real deployments (see `.env.example` at the repo root).
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object for the backend application.

    Grouped by the architecture layer each setting belongs to, so this file stays
    readable as later phases add their own configuration (detection model paths,
    Fabric connection profiles, LLM provider settings, etc.).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_name: str = "Patient-Aware Cyber Resilience Platform"
    environment: str = Field(default="development", description="development | test | production")
    debug: bool = Field(default=True)

    # --- API ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # --- Database (PostgreSQL + TimescaleDB extension) ---
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/patient_aware_cyber_resilience",
        description="Relational + time-series store. TimescaleDB runs as an extension on this same "
        "Postgres instance.",
    )

    # --- Logging ---
    log_level: str = Field(default="INFO", description="DEBUG | INFO | WARNING | ERROR | CRITICAL")
    log_json: bool = Field(
        default=False,
        description="Emit structured JSON logs. Useful in CI/production; human-readable in local "
        "dev by default.",
    )

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor.

    FastAPI dependencies should call this rather than instantiating `Settings()`
    directly, so configuration is read once per process and can be overridden
    cleanly in tests via dependency overrides.
    """
    return Settings()
