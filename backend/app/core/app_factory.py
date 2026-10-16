"""FastAPI application factory.

Kept as a factory (rather than a module-level `app = FastAPI()`) so tests can
construct an isolated app instance with overridden settings/dependencies, and so
later phases can register new routers in one place as they're built, instead of
editing a growing `main.py`.
"""

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and return a configured FastAPI application.

    Args:
        settings: Optional explicit settings, primarily for tests. Defaults to the
            cached process-wide settings.
    """
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_output=settings.log_json)

    app = FastAPI(
        title=settings.app_name,
        description=(
            "Research-grade, patient-aware autonomous cyber-resilience platform for "
            "healthcare IoMT. See /docs/architecture.md for the full architecture "
            "specification."
        ),
        version="0.1.0",
        debug=settings.debug,
    )

    _register_middleware(app, settings)
    _register_state(app, settings)
    _register_routers(app)

    return app


def _register_middleware(app: FastAPI, settings: Settings) -> None:
    """Phase 10: the SOC dashboard (`frontend/`) runs on its own origin (the
    Vite dev server, and a separate container in the Docker deployment
    Section 14 describes), so the browser enforces CORS against this API
    regardless of how much this backend 'trusts' the frontend. Explicit
    origin allowlist from `Settings.cors_allowed_origins` -- never a
    wildcard, and credentials are not allowed cross-origin (this API has no
    cookie-based auth to carry; Section 15 notes auth itself is still only
    designed-for, not implemented).
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Added after CORS so they sit OUTSIDE it (Starlette runs the last-added
    # middleware first): an over-limit request is refused before any routing.
    # Both are no-ops at their default of 0.
    from app.core.limits import BodySizeLimitMiddleware, RateLimitMiddleware

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(RateLimitMiddleware, per_minute=settings.rate_limit_per_minute)


def _register_state(app: FastAPI, settings: Settings) -> None:
    """Initialize app-wide, in-process state.

    Phase 2 introduced the first such state: an in-memory device registry
    seeded with the default smart-hospital fleet. Phase 9 adds every other
    in-memory repository/store built in Phases 4-8 (`app/repositories/*.py`,
    `app/blockchain/outbox.py`) as `app.state` singletons, following the
    exact same pattern `get_device_registry` already established in
    `app/api/dependencies.py` — created once here, handed to routes via
    dependency injection, never imported as a bare module-level global, so
    tests can override any of them with `app.dependency_overrides`.

    These repositories are in-memory by default. Section 8's storage
    strategy names PostgreSQL/TimescaleDB as the eventual store; a real,
    Postgres-backed implementation of each of these (except
    `network_event_store`/`telemetry_store`, a deliberately separate,
    still-pending TimescaleDB-hypertable task -- see `app/models/orm.py`'s
    module docstring) is wired in below when
    `settings.repository_backend == "postgres"`. Defaults to `"memory"`,
    so the existing 359 backend tests and CI (which brings up no Postgres
    service) are completely unaffected either way.
    """
    from app.blockchain.fabric_client import SubprocessFabricClient
    from app.blockchain.mock_fabric_client import MockFabricClient
    from app.blockchain.outbox import OutboxRepository, PostgresOutboxRepository
    from app.blockchain.outbox_worker import OutboxWorker
    from app.iomt_simulator.hospital import build_default_fleet
    from app.repositories.agent_traces import AgentTraceRecorder, PostgresAgentTraceRecorder
    from app.repositories.incidents import IncidentRepository, PostgresIncidentRepository
    from app.repositories.recovery_results import (
        PostgresRecoveryResultRepository,
        RecoveryResultRepository,
    )
    from app.repositories.responses import (
        ExecutedResponseRepository,
        PostgresExecutedResponseRepository,
        PostgresProposedResponseRepository,
        ProposedResponseRepository,
    )
    from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore

    # Post-Phase-15: so app/core/auth.py's get_current_principal dependency
    # can read auth_enabled/api_keys without its own separate DI wiring --
    # every other `Settings`-derived decision in this function already
    # closes over `settings` directly; auth needs it reachable from a
    # FastAPI dependency function instead, hence app.state.
    app.state.settings = settings

    app.state.device_registry = build_default_fleet()

    if settings.repository_backend == "postgres":
        # Real Postgres required (see `app/core/db.py` for the sync-driver
        # tradeoff this mode accepts). Not the default, because most
        # environments running this app (including its own default
        # dev/test runs and CI) have no Postgres reachable at
        # `settings.database_url`.
        from app.core.db import build_engine, build_session_factory, create_all_tables

        engine = build_engine(settings.database_url)
        create_all_tables(engine)
        session_factory = build_session_factory(engine)
        app.state.db_engine = engine
        app.state.incident_repository = PostgresIncidentRepository(session_factory)
        app.state.agent_trace_recorder = PostgresAgentTraceRecorder(session_factory)
        app.state.recovery_result_repository = PostgresRecoveryResultRepository(session_factory)
        app.state.proposed_response_repository = PostgresProposedResponseRepository(session_factory)
        app.state.executed_response_repository = PostgresExecutedResponseRepository(session_factory)
        app.state.outbox_repository = PostgresOutboxRepository(session_factory)
        # Time-series stores (events, telemetry): Postgres tables, converted to
        # TimescaleDB hypertables when the extension exists (plain tables otherwise;
        # the outcome is logged and kept on app.state for /health-style inspection).
        from app.core.db import create_hypertables
        from app.repositories.telemetry_events import PostgresNetworkEventStore, PostgresTelemetryStore

        app.state.hypertable_status = create_hypertables(engine)
        _logger.info("time-series table storage: %s", app.state.hypertable_status)
        app.state.network_event_store = PostgresNetworkEventStore(session_factory)
        app.state.telemetry_store = PostgresTelemetryStore(session_factory)
    else:
        app.state.incident_repository = IncidentRepository()
        app.state.agent_trace_recorder = AgentTraceRecorder()
        app.state.recovery_result_repository = RecoveryResultRepository()
        app.state.proposed_response_repository = ProposedResponseRepository()
        app.state.executed_response_repository = ExecutedResponseRepository()
        app.state.outbox_repository = OutboxRepository()
        app.state.network_event_store = NetworkEventStore()
        app.state.telemetry_store = TelemetryStore()

    if settings.fabric_client_mode == "subprocess":
        # Real native-Fabric network required (blockchain/network/README.md)
        # -- not the default, because most environments running this app
        # (including its own default dev/test runs) don't have one up.
        scripts_dir = Path(settings.fabric_network_scripts_dir)
        if not scripts_dir.is_absolute():
            scripts_dir = (_BACKEND_DIR / scripts_dir).resolve()
        app.state.fabric_client = SubprocessFabricClient(
            network_scripts_dir=scripts_dir, chaincode_name=settings.fabric_chaincode_name
        )
    else:
        app.state.fabric_client = MockFabricClient()

    # The worker itself is NOT started as a background task here -- Section
    # 7 step 13 says outbox draining "never blocks" the request path, but
    # actually running an unattended asyncio loop for the lifetime of the
    # app is a deployment/lifespan concern (uvicorn lifespan events,
    # supervising crashes, etc.) this phase's gate does not require.
    # `/blockchain/audit`'s `process` endpoint calls `process_once()`
    # on demand instead -- real draining, just not automatic yet. See
    # `app/blockchain/README.md`'s own "`run_forever()` is what a real
    # deployment runs ... tests call `process_once()` directly" note.
    app.state.outbox_worker = OutboxWorker(app.state.outbox_repository, app.state.fabric_client)

    # --- Agent orchestration (post-Phase-15) ---
    # `log_handler`: the real, bounded in-memory log capture the five agents'
    # `get_logs` tool reads from (`app/repositories/log_capture.py`) -- one
    # per app instance, installed once here rather than per-request, so log
    # lines emitted by any route/service during this process's lifetime are
    # genuinely queryable, not a fresh empty buffer every request.
    from app.repositories.log_capture import install as install_log_capture

    app.state.log_handler = install_log_capture()

    # `llm_client`: which real `LLMClient` the orchestrator constructs for
    # the five agents to call through (`app/agents/llm_client.py`). Mirrors
    # `fabric_client_mode`/`repository_backend`'s mock-default pattern.
    # Falls back to `MockLLMClient` (with a logged warning, not a silent
    # swap) if `llm_backend="gemini"` is requested but no API key is
    # configured -- constructing a `GeminiLLMClient` that would fail on its
    # very first call is worse than running mock and saying so.
    from app.agents.llm_client import GeminiLLMClient, MockLLMClient

    if settings.llm_backend == "gemini" and settings.gemini_api_key:
        app.state.llm_client = GeminiLLMClient(
            api_key=settings.gemini_api_key, model=settings.gemini_model
        )
    else:
        if settings.llm_backend == "gemini":
            _logger.warning(
                "llm_backend='gemini' was requested but GEMINI_API_KEY is empty -- falling back "
                "to MockLLMClient. Set GEMINI_API_KEY (get one at "
                "https://aistudio.google.com/app/apikey) to actually use Gemini."
            )
        app.state.llm_client = MockLLMClient(responses=[])

    # `risk_model`: the real deterministic dual-risk engine (Phase 5) the
    # orchestrator scores every candidate response against -- the same
    # `RuleBasedRiskModel` instance `/risk-assessments` constructs, just
    # shared here so the orchestrator doesn't need its own.
    from app.risk_engine.rule_based import RuleBasedRiskModel

    app.state.risk_model = RuleBasedRiskModel()


def _register_routers(app: FastAPI) -> None:
    """Register all API routers.

    Phase 1 registered only the health router. Each later phase (detection,
    agents, risk engine, etc.) adds its router here as it's built — this
    function is the single place that has to change to wire in a new resource.
    """
    from fastapi import Depends

    from app.api.agents import router as agents_router
    from app.api.blockchain_audit import router as blockchain_audit_router
    from app.api.detections import router as detections_router
    from app.api.devices import router as devices_router
    from app.api.events import router as events_router
    from app.api.health import router as health_router
    from app.api.incidents import router as incidents_router
    from app.api.recovery import router as recovery_router
    from app.api.responses import router as responses_router
    from app.api.risk_assessments import router as risk_assessments_router
    from app.api.telemetry import router as telemetry_router
    from app.core.auth import get_current_principal

    # Post-Phase-15: every router except /health requires a resolved
    # Principal (app/core/auth.py) -- a no-op when Settings.auth_enabled
    # is false (the default), a real X-API-Key check when true. /health is
    # deliberately exempt: a liveness probe should not need credentials.
    _auth = [Depends(get_current_principal)]

    app.include_router(health_router)
    app.include_router(devices_router, dependencies=_auth)
    app.include_router(detections_router, dependencies=_auth)
    app.include_router(telemetry_router, dependencies=_auth)
    app.include_router(events_router, dependencies=_auth)
    app.include_router(incidents_router, dependencies=_auth)
    app.include_router(risk_assessments_router, dependencies=_auth)
    app.include_router(agents_router, dependencies=_auth)
    app.include_router(responses_router, dependencies=_auth)
    app.include_router(recovery_router, dependencies=_auth)
    app.include_router(blockchain_audit_router, dependencies=_auth)
