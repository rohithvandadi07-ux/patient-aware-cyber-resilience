"""FastAPI application factory.

Kept as a factory (rather than a module-level `app = FastAPI()`) so tests can
construct an isolated app instance with overridden settings/dependencies, and so
later phases can register new routers in one place as they're built, instead of
editing a growing `main.py`.
"""

from pathlib import Path

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

_BACKEND_DIR = Path(__file__).resolve().parents[2]


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

    _register_state(app, settings)
    _register_routers(app)

    return app


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

    These are still in-memory, not Postgres-backed — Section 8's storage
    strategy names PostgreSQL/TimescaleDB as the eventual store, but Phase
    9's own gate (Section 19) is "all resource routers from Section 15
    exist and are covered by API tests," not a database migration. Wiring a
    real Postgres layer underneath these same repository interfaces is
    later, explicitly deferred work, not something this phase claims to
    have done.
    """
    from app.blockchain.fabric_client import SubprocessFabricClient
    from app.blockchain.mock_fabric_client import MockFabricClient
    from app.blockchain.outbox import OutboxRepository
    from app.blockchain.outbox_worker import OutboxWorker
    from app.iomt_simulator.hospital import build_default_fleet
    from app.repositories.agent_traces import AgentTraceRecorder
    from app.repositories.incidents import IncidentRepository
    from app.repositories.recovery_results import RecoveryResultRepository
    from app.repositories.responses import ExecutedResponseRepository, ProposedResponseRepository
    from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore

    app.state.device_registry = build_default_fleet()
    app.state.incident_repository = IncidentRepository()
    app.state.network_event_store = NetworkEventStore()
    app.state.telemetry_store = TelemetryStore()
    app.state.agent_trace_recorder = AgentTraceRecorder()
    app.state.recovery_result_repository = RecoveryResultRepository()
    app.state.proposed_response_repository = ProposedResponseRepository()
    app.state.executed_response_repository = ExecutedResponseRepository()
    app.state.outbox_repository = OutboxRepository()

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


def _register_routers(app: FastAPI) -> None:
    """Register all API routers.

    Phase 1 registered only the health router. Each later phase (detection,
    agents, risk engine, etc.) adds its router here as it's built — this
    function is the single place that has to change to wire in a new resource.
    """
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

    app.include_router(health_router)
    app.include_router(devices_router)
    app.include_router(detections_router)
    app.include_router(telemetry_router)
    app.include_router(events_router)
    app.include_router(incidents_router)
    app.include_router(risk_assessments_router)
    app.include_router(agents_router)
    app.include_router(responses_router)
    app.include_router(recovery_router)
    app.include_router(blockchain_audit_router)
