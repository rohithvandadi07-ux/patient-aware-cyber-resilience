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
    debug: bool = Field(
        default=False,
        description="Passed straight through to FastAPI's own `debug` flag (`app_factory.py`), which "
        "controls Starlette's `ServerErrorMiddleware` -- when true, an unhandled exception returns a "
        "full traceback (internal file paths, source lines, local variable values) in the HTTP "
        "response body instead of a generic 500. Phase 12 security pass: defaults to false (fail "
        "safe) rather than true, since a security-relevant default should not require an operator to "
        "remember to turn it off before anything is ever exposed. Local development opts in "
        "explicitly via `DEBUG=true` in `.env` (see `.env.example`) rather than inheriting it silently "
        "from this default.",
    )

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

    # --- Authentication/authorization (post-Phase-15, user-directed) ---
    # Carried-forward gap since Phase 9 (docs/security-checklist.md Section
    # 6: "designed-for, not implemented") -- this closes it. Mirrors every
    # other mock/opt-in flag above: `auth_enabled` defaults to `False` so
    # every pre-existing test and the default dev experience are completely
    # unaffected; set it `True` (with real keys configured) for anything
    # resembling a real deployment.
    auth_enabled: bool = Field(
        default=False,
        description="When true, every route except /health requires a valid X-API-Key header "
        "(see app/core/auth.py), resolved against api_keys below to an identity + role. When "
        "false (the default), every request is treated as an implicit 'approver'-role principal "
        "named 'anonymous (auth disabled)' -- the same permissive default this app has always had, "
        "just now named explicitly rather than having no concept of a principal at all.",
    )
    api_keys: dict[str, tuple[str, str]] = Field(
        default_factory=dict,
        description="API_KEY -> (role, identity) map. role is one of 'viewer' | 'operator' | "
        "'approver' (app/core/auth.py's _ROLE_RANK -- viewer can read, operator can trigger "
        "/incidents/{id}/investigate without auto-approving, approver can additionally approve/"
        "execute responses and auto-approve an investigation cycle). Set via the API_KEYS "
        "environment variable as 'key1:role1:identity1,key2:role2:identity2' -- never committed; "
        "see .env.example. Empty by default, which is only safe because auth_enabled defaults to "
        "False; turning auth_enabled on with no keys configured locks out every route but /health, "
        "deliberately (fail closed, not open).",
    )

    # --- Database (PostgreSQL + TimescaleDB extension) ---
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/patient_aware_cyber_resilience",
        description="Relational + time-series store. TimescaleDB runs as an extension on this same "
        "Postgres instance. `repository_backend='postgres'` connects here via a sync driver "
        "(`app/core/db.py` converts this URL's dialect accordingly) -- this setting is still the "
        "single source of truth for where the database is, regardless of which driver talks to it.",
    )
    repository_backend: str = Field(
        default="memory",
        description="'memory' | 'postgres' -- which repository implementation backs incidents, "
        "agent traces, recovery results, proposed/executed responses, and the blockchain outbox "
        "(app/core/app_factory.py's `_register_state`). Defaults to 'memory' because most "
        "environments running this app (including its own default dev/test runs and CI, which "
        "brings up no Postgres service) have no Postgres reachable at `database_url`; the existing "
        "359 backend tests exercise the in-memory repositories exclusively and are unaffected by "
        "this setting either way. Set to 'postgres' once a real Postgres is reachable (docker-compose "
        "provides one; see `app/core/db.py` for the sync-driver tradeoff this mode accepts) to get "
        "real durable storage instead of an in-process dict/list that a process restart discards. "
        "Mirrors `fabric_client_mode`'s mock-default-until-the-real-thing-is-up pattern below. Does "
        "NOT cover `NetworkEventStore`/`TelemetryStore` (still in-memory; a separate, later "
        "TimescaleDB-hypertable task) or the IoMT simulator's `DeviceRegistry` (live simulation "
        "state, not a persisted catalog) -- see `app/models/orm.py`'s module docstring.",
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

    # --- Agent LLM backend (post-Phase-15, user-directed) ---
    llm_backend: str = Field(
        default="mock",
        description="'mock' | 'gemini' -- which LLMClient implementation the orchestrator "
        "(app/orchestration/orchestrator.py) constructs for the five agents to call through "
        "(app/agents/llm_client.py). Mirrors fabric_client_mode/repository_backend's "
        "mock-default-until-opted-in pattern. Defaults to 'mock' because most environments "
        "(including this app's own default dev/test runs, and every pre-existing agent test) "
        "have no API key configured; app_factory.py falls back to 'mock' with a logged warning "
        "even when 'gemini' is requested but gemini_api_key is empty, rather than constructing a "
        "client that would fail on its first real call.",
    )
    gemini_api_key: str = Field(
        default="",
        description="API key for GeminiLLMClient, read from the GEMINI_API_KEY environment "
        "variable. Get one at https://aistudio.google.com/app/apikey. Never committed -- see "
        ".env.example. Empty by default; llm_backend='gemini' with this unset falls back to mock.",
    )
    gemini_model: str = Field(
        default="gemini-2.0-flash",
        description="Gemini model name passed to GeminiLLMClient. gemini-2.0-flash is Google's "
        "fast/cheap tier, adequate for this project's structured-JSON agent outputs; override via "
        "GEMINI_MODEL for a different tier.",
    )

    # --- Request limits (post-Phase-15, opt-in) ---
    rate_limit_per_minute: int = Field(
        default=0,
        ge=0,
        description="Max requests per client per minute (fixed window; client = API key when "
        "sent, else peer IP; /health exempt). 0 disables. In-process state, so each worker "
        "process enforces its own window -- see app/core/limits.py.",
    )
    max_request_body_bytes: int = Field(
        default=0,
        ge=0,
        description="Reject request bodies larger than this with 413. 0 disables. A "
        "`/detections/score-flows` batch of 1000 flows is roughly 1 MB of JSON, so values "
        "below ~2 MB would reject a full batch.",
    )

    # --- Policy Engine confidence gate (post-Phase-15, opt-in) ---
    policy_min_autonomous_confidence: float | None = Field(
        default=None,
        gt=0.0,
        le=1.0,
        description="When set, the Policy Engine sends an otherwise-autonomous action to human "
        "approval if the detector's confidence is below this value (or not supplied). Unset (the "
        "default) leaves the engine exactly as Section 13 specifies. See "
        "`evaluation/confidence_gating.md` and `evaluation/calibrated_gating.md` for what it does "
        "on the real detector; the value must be calibrated on validation data, not guessed.",
    )

    # --- Real-data detector (post-Phase-15) ---
    real_detector_model_path: str = Field(
        default="../experiments/models/ciciomt2024_xgboost.joblib",
        description="Path to the real CICIoMT2024 19-class model written by "
        "`python -m app.cybersecurity.train_ciciomt2024` (its `.metadata.json` must sit beside it). "
        "Used only by `POST /detections/score-flows`; the artifact is gitignored, so that endpoint "
        "returns 503 with training instructions until one exists. Relative paths resolve against "
        "the backend working directory.",
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

    @field_validator("api_keys", mode="before")
    @classmethod
    def _parse_api_keys(cls, value: object) -> object:
        """Same friendlier-than-raw-JSON `.env` shape `cors_allowed_origins`
        parses above: 'key1:role1:identity1,key2:role2:identity2' from the
        environment, split into {key: (role, identity)}. Raises ValueError
        (surfaced by pydantic-settings as a startup config error, not a
        silent skip) on a malformed entry -- a typo'd key here should fail
        loudly at startup, not quietly grant no access or the wrong role."""
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped:
            return {}
        parsed: dict[str, tuple[str, str]] = {}
        for entry in stripped.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            if len(parts) != 3:
                raise ValueError(
                    f"API_KEYS entry {entry!r} must be 'key:role:identity' -- got {len(parts)} "
                    "colon-separated parts"
                )
            key, role, identity = (p.strip() for p in parts)
            parsed[key] = (role, identity)
        return parsed

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
