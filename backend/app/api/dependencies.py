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

from fastapi import Request

from app.blockchain.fabric_client import FabricClient
from app.blockchain.outbox import OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.iomt_simulator.registry import DeviceRegistry
from app.policy_engine.engine import PolicyEngine
from app.recovery.engine import RecoveryOrchestrator
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.recovery_results import RecoveryResultRepository
from app.repositories.responses import ExecutedResponseRepository, ProposedResponseRepository
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.response_engine.orchestrator import ResponseOrchestrator


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


def get_policy_engine() -> PolicyEngine:
    """Stateless (no LLM call, no stored state -- see `app/policy_engine/`),
    so a fresh instance per request is equivalent to a shared one; not
    cached on `app.state` because there is nothing to share."""
    return PolicyEngine()


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
