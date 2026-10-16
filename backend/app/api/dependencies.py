"""Shared FastAPI dependencies.

Phase 2 introduced the first piece of app-wide state: a single in-memory
DeviceRegistry, created once at app startup and handed to routes via
dependency injection — never imported as a bare module-level global, so tests
can override it with `app.dependency_overrides`.

Phase 9 adds one dependency per `app.state` singleton `app_factory.py` now
registers, following that exact pattern, plus three thin factory
dependencies (`get_policy_engine`, `get_response_orchestrator`,
`get_recovery_orchestrator`) for the stateless L6/L7/L8 service objects —
these don't hold state of their own, but routers need them constructed with
the right repositories/registry, so they're assembled here rather than each
router re-wiring its own.
"""

from fastapi import Depends, Request

from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.blockchain.fabric_client import FabricClient
from app.blockchain.outbox import OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.core.config import Settings, get_settings
from app.iomt_simulator.registry import DeviceRegistry
from app.orchestration.orchestrator import IncidentOrchestrator
from app.policy_engine.engine import PolicyEngine
from app.recovery.engine import RecoveryOrchestrator
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.recovery_results import RecoveryResultRepository
from app.repositories.responses import ExecutedResponseRepository, ProposedResponseRepository
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.response_engine.orchestrator import ResponseOrchestrator
from app.risk_engine.model import RiskModel


def get_device_registry(request: Request) -> DeviceRegistry:
    return request.app.state.device_registry


def get_incident_repository(request: Request) -> IncidentRepository:
    return request.app.state.incident_repository


def get_network_event_store(request: Request) -> NetworkEventStore:
    return request.app.state.network_event_store


def get_telemetry_store(request: Request) -> TelemetryStore:
    return request.app.state.telemetry_store


def get_agent_trace_recorder(request: Request) -> AgentTraceRecorder:
    return request.app.state.agent_trace_recorder


def get_recovery_result_repository(request: Request) -> RecoveryResultRepository:
    return request.app.state.recovery_result_repository


def get_proposed_response_repository(request: Request) -> ProposedResponseRepository:
    return request.app.state.proposed_response_repository


def get_executed_response_repository(request: Request) -> ExecutedResponseRepository:
    return request.app.state.executed_response_repository


def get_outbox_repository(request: Request) -> OutboxRepository:
    return request.app.state.outbox_repository


def get_fabric_client(request: Request) -> FabricClient:
    return request.app.state.fabric_client


def get_outbox_worker(request: Request) -> OutboxWorker:
    return request.app.state.outbox_worker


def get_policy_engine(settings: Settings = Depends(get_settings)) -> PolicyEngine:
    """Stateless (no LLM call, no stored state -- see `app/policy_engine/`),
    so a fresh instance per request is equivalent to a shared one; not
    cached on `app.state` because there is nothing to share. The optional
    confidence gate comes from `Settings.policy_min_autonomous_confidence`
    (off by default)."""
    return PolicyEngine(min_autonomous_confidence=settings.policy_min_autonomous_confidence)


def get_response_orchestrator(request: Request) -> ResponseOrchestrator:
    return ResponseOrchestrator(
        device_registry=request.app.state.device_registry,
        incident_repository=request.app.state.incident_repository,
    )


def get_recovery_orchestrator(request: Request) -> RecoveryOrchestrator:
    return RecoveryOrchestrator(
        incident_repository=request.app.state.incident_repository,
        recovery_result_repository=request.app.state.recovery_result_repository,
    )


def get_llm_client(request: Request) -> LLMClient:
    """Post-Phase-15: whichever `LLMClient` `_register_state` constructed
    per `Settings.llm_backend` -- `MockLLMClient` by default, a real
    `GeminiLLMClient` when `llm_backend="gemini"` and a key is configured."""
    return request.app.state.llm_client


def get_risk_model(request: Request) -> RiskModel:
    return request.app.state.risk_model


def get_agent_toolkit(request: Request) -> AgentToolkit:
    """Builds the same `AgentToolkit` shape
    `tests/test_lifecycle_integration.py`'s `_build_toolkit` helper does --
    wired to this app's own `app.state` singletons, so a trace recorded via
    the orchestrator is retrievable through `GET /agents/{incident_id}` on
    this same running app."""
    return AgentToolkit(
        device_registry=request.app.state.device_registry,
        incident_repository=request.app.state.incident_repository,
        network_event_store=request.app.state.network_event_store,
        telemetry_store=request.app.state.telemetry_store,
        log_handler=request.app.state.log_handler,
        trace_recorder=request.app.state.agent_trace_recorder,
        recovery_result_repository=request.app.state.recovery_result_repository,
    )


def get_incident_orchestrator(request: Request) -> IncidentOrchestrator:
    """Post-Phase-15: the real multi-agent pipeline sequencer
    (`app/orchestration/orchestrator.py`), constructed fresh per request
    from this app's own `app.state` singletons -- stateless itself, same
    reasoning as `get_policy_engine`/`get_response_orchestrator` above."""
    app_state = request.app.state
    return IncidentOrchestrator(
        client=app_state.llm_client,
        toolkit=get_agent_toolkit(request),
        incident_repository=app_state.incident_repository,
        proposed_response_repository=app_state.proposed_response_repository,
        executed_response_repository=app_state.executed_response_repository,
        response_orchestrator=get_response_orchestrator(request),
        recovery_orchestrator=get_recovery_orchestrator(request),
        outbox_repository=app_state.outbox_repository,
        risk_model=app_state.risk_model,
        policy_engine=get_policy_engine(get_settings()),
    )
