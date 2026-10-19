"""Demo mode (M9): reset the whole platform to a clean starting state.

`GET /demo/status` always answers (so the console knows whether to show the
Demo page). `POST /demo/reset` exists only when `Settings.demo_mode` is true
-- otherwise it returns the same 404 as a route that does not exist, so a
real deployment cannot wipe its own audit trail. When enabled it also needs
the `approver` role.

It clears incidents, traces, proposed/executed responses, recovery results,
the audit outbox, and stored events/telemetry, and returns the simulated
hospital (devices, patients, patient clock) to its seeded state. Device and
patient registries are refilled IN PLACE, because other objects hold a
reference to them. With the mock Fabric client the mock ledger is reset too;
a real Fabric ledger is append-only and is never touched.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.auth import Principal, get_current_principal, require_role

router = APIRouter(prefix="/demo", tags=["demo"])
_logger = logging.getLogger(__name__)


class DemoStatus(BaseModel):
    enabled: bool


class DemoResetResult(BaseModel):
    incidents_removed: int
    proposed_removed: int
    executed_removed: int
    traces_removed: int


def _refill(target: object, fresh: object) -> None:
    """Replace `target`'s state with `fresh`'s, keeping `target`'s identity."""
    target.__dict__.clear()
    target.__dict__.update(fresh.__dict__)


@router.get("/status", response_model=DemoStatus)
def demo_status(request: Request) -> DemoStatus:
    return DemoStatus(enabled=bool(request.app.state.settings.demo_mode))


@router.post("/reset", response_model=DemoResetResult)
def demo_reset(
    request: Request, principal: Principal = Depends(get_current_principal)
) -> DemoResetResult:
    state = request.app.state
    if not state.settings.demo_mode:
        raise HTTPException(status_code=404, detail="Not Found")
    require_role(principal, "approver")

    result = DemoResetResult(
        incidents_removed=len(state.incident_repository.list_all()),
        proposed_removed=len(state.proposed_response_repository.list_all()),
        executed_removed=len(state.executed_response_repository.list_all()),
        traces_removed=len(state.agent_trace_recorder.all_traces()),
    )

    state.incident_repository.clear()
    state.agent_trace_recorder.clear()
    state.proposed_response_repository.clear()
    state.executed_response_repository.clear()
    state.recovery_result_repository.clear()
    state.outbox_repository.clear()
    state.network_event_store.clear()
    state.telemetry_store.clear()

    from app.iomt_simulator.hospital import build_default_fleet
    from app.iomt_simulator.patients import build_default_patients

    _refill(state.device_registry, build_default_fleet())
    _refill(state.patient_registry, build_default_patients())

    from app.blockchain.mock_fabric_client import MockFabricClient

    if isinstance(state.fabric_client, MockFabricClient):
        _refill(state.fabric_client, MockFabricClient())

    _logger.warning("demo reset performed by %s: %s", principal.identity, result.model_dump())
    return result
