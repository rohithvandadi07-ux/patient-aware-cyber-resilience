"""Application settings, loaded from environment variables.

Nothing in this codebase hardcodes a host, port, secret, or environment-specific
path. Every configurable value is declared here with an explicit default (safe for
local development only) and is expected to be overridden via environment variables
or a `.env` file in real deployments (see `.env.example` at the repo root).
"""

import json
from functools import lru_cache

from pydantic import Field, field_validator
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
    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:5173", "http://127.0.0.1:5173"],
        description="Origins the SOC dashboard (Phase 10, Vite dev server default port 5173) may "
        "call this API from. Needed because the frontend and backend run as separate origins in "
        "local dev (and, per Section 14's Docker-based deployment, in docker-compose too) -- a "
        "browser enforces CORS regardless of whether this backend 'trusts' the frontend. Never "
        "'*' -- an explicit, reviewable list, overridable via the CORS_ALLOWED_ORIGINS env var "
        "(comma-separated, or a JSON array) for a real deployment's actual frontend origin.",
    )

    # --- Database (PostgreSQL + TimescaleDB extension) ---
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/patient_aware_cyber_resilience",
        description="Relational + time-series store. TimescaleDB runs as an extension on this same "
        "Postgres instance.",
    )

    # --- Blockchain (L9, architecture spec Section 14) ---
    fabric_network_scripts_dir: str = Field(
        default="../blockchain/network/scripts",
        description="Directory containing invoke.sh/query.sh -- see blockchain/network/README.md. "
        "SubprocessFabricClient shells out to these rather than using a Fabric SDK binding "
        "(none exists in this backend yet).",
    )
    fabric_chaincode_name: str = Field(
        default="provenance",
        description="Chaincode name as committed via blockchain/network/scripts/deploy-chaincode.sh.",
    )
    fabric_client_mode: str = Field(
        default="mock",
        description="'mock' | 'subprocess' -- which FabricClient implementation backs the outbox "
        "worker in this process (app/blockchain/outbox_worker.py). Defaults to 'mock' because most "
        "environments running this app (including its own default dev/test runs) have no live "
        "Fabric network up; the real native-Fabric network in blockchain/network/ is brought up "
        "explicitly (see blockchain/network/README.md), the same precondition "
        "backend/tests/test_blockchain_integration.py gates on. Set to 'subprocess' only once that "
        "network is actually running, to get real on-chain commits instead of an in-memory double.",
    )

    # --- Logging ---
    log_level: str = Field(default="INFO", description="DEBUG | INFO | WARNING | ERROR | CRITICAL")
    log_json: bool = Field(
        default=False,
        description="Emit structured JSON logs. Useful in CI/production; human-readable in local "
        "dev by default.",
    )

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _parse_cors_allowed_origins(cls, value: object) -> object:
        """`pydantic-settings` only parses a `list[str]` env var as JSON by
        default -- a plain `CORS_ALLOWED_ORIGINS=http://a,http://b` would
        otherwise fail to load rather than split, which is the friendlier,
        more commonly expected `.env` shape for a list of origins. Accepts
        either: a JSON array string parses as JSON; anything else is split
        on commas and stripped. A non-string value (the Python-level
        default list, or a value already parsed by a caller) passes through
        unchanged."""
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if stripped.startswith("["):
            return json.loads(stripped)
        return [origin.strip() for origin in stripped.split(",") if origin.strip()]

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
