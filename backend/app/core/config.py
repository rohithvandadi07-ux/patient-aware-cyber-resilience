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
