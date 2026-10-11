from datetime import UTC, datetime

import pytest

from app.iomt_simulator.device import InfusionPump, Ventilator
from app.iomt_simulator.registry import DeviceNotFoundError, DeviceRegistry
from app.repositories.incidents import IncidentNotFoundError, IncidentRepository
from app.response_engine.orchestrator import (
    ApprovalRequiredError,
    ResponseOrchestrator,
    ResponseRejectedError,
)
from app.schemas.device import OperationalState
from app.schemas.enums import ApprovalDecision, ResponseActionCategory
from app.schemas.policy import PolicyDecision
from app.schemas.response import ApprovalRecord

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def registry() -> DeviceRegistry:
    reg = DeviceRegistry()
    reg.register(
        Ventilator(device_id="ventilator-01", criticality="high", patient_dependency=True)
    )
    reg.register(
        InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False)
    )
    return reg


@pytest.fixture
def incidents(registry: DeviceRegistry) -> IncidentRepository:
    repo = IncidentRepository()
    repo.create("incident-vent", device_id="ventilator-01")
    repo.create("incident-pump", device_id="pump-01")
    return repo


@pytest.fixture
def orchestrator(registry: DeviceRegistry, incidents: IncidentRepository) -> ResponseOrchestrator:
    return ResponseOrchestrator(device_registry=registry, incident_repository=incidents)


def _decision(
    incident_id: str,
    action: ResponseActionCategory,
    requires_human_approval: bool,
) -> PolicyDecision:
    return PolicyDecision(
        incident_id=incident_id,
        chosen_action=action,
        requires_human_approval=requires_human_approval,
        policy_rule_id="test_rule",
        rationale="test",
    )


def _approval(
    incident_id: str, decision: ApprovalDecision = ApprovalDecision.APPROVED, approver: str = "dr.lee"
) -> ApprovalRecord:
    return ApprovalRecord(
        incident_id=incident_id, approver_identity=approver, decision=decision, timestamp=_NOW
    )


# --- approval gating --------------------------------------------------------


def test_autonomous_action_executes_immediately_with_no_approval_needed(orchestrator):
    decision = _decision("incident-pump", ResponseActionCategory.ISOLATE_NON_CRITICAL, False)

    result = orchestrator.execute(decision)

    assert result.executed_by == "system"
    assert result.action_taken == ResponseActionCategory.ISOLATE_NON_CRITICAL
    assert result.incident_id == "incident-pump"
    assert result.chain_tx_id is None


def test_autonomous_action_ignores_an_irrelevant_approval_if_one_is_passed(orchestrator):
    # requires_human_approval=False means the gate never looks at `approval`
    # at all -- passing one (even a rejected one) must not change anything.
    decision = _decision("incident-pump", ResponseActionCategory.ISOLATE_NON_CRITICAL, False)
    rejected = _approval("incident-pump", decision=ApprovalDecision.REJECTED)

    result = orchestrator.execute(decision, approval=rejected)

    assert result.executed_by == "system"


def test_approval_required_and_none_given_raises_approval_required_error(orchestrator):
    decision = _decision("incident-vent", ResponseActionCategory.SHUTDOWN, True)

    with pytest.raises(ApprovalRequiredError, match="incident-vent"):
        orchestrator.execute(decision, approval=None)


def test_approval_required_and_rejected_raises_response_rejected_error(orchestrator):
    decision = _decision("incident-vent", ResponseActionCategory.SHUTDOWN, True)
    rejection = _approval("incident-vent", decision=ApprovalDecision.REJECTED)

    with pytest.raises(ResponseRejectedError, match="rejected"):
        orchestrator.execute(decision, approval=rejection)


def test_approval_with_mismatched_incident_id_raises_value_error(orchestrator):
    decision = _decision("incident-vent", ResponseActionCategory.SHUTDOWN, True)
    wrong_incident_approval = _approval("some-other-incident")

    with pytest.raises(ValueError, match="incident"):
        orchestrator.execute(decision, approval=wrong_incident_approval)


def test_approval_required_and_approved_executes_with_approver_as_executed_by(orchestrator):
    decision = _decision("incident-vent", ResponseActionCategory.SHUTDOWN, True)
    approval = _approval("incident-vent", approver="dr.lee")

    result = orchestrator.execute(decision, approval=approval)

    assert result.executed_by == "dr.lee"
    assert result.action_taken == ResponseActionCategory.SHUTDOWN


# --- incident/device lookup --------------------------------------------------


def test_unknown_incident_id_raises_incident_not_found(orchestrator):
    decision = _decision("no-such-incident", ResponseActionCategory.ISOLATE_NON_CRITICAL, False)

    with pytest.raises(IncidentNotFoundError):
        orchestrator.execute(decision)


def test_incident_referencing_an_unregistered_device_raises_device_not_found(incidents, registry):
    incidents.create("incident-orphan", device_id="ghost-device")
    orchestrator = ResponseOrchestrator(device_registry=registry, incident_repository=incidents)
    decision = _decision("incident-orphan", ResponseActionCategory.ISOLATE_NON_CRITICAL, False)

    with pytest.raises(DeviceNotFoundError):
        orchestrator.execute(decision)


# --- correct device state mutation per supported action category -----------


def test_shutdown_powers_off_the_device(orchestrator, registry):
    decision = _decision("incident-vent", ResponseActionCategory.SHUTDOWN, True)
    orchestrator.execute(decision, approval=_approval("incident-vent"))

    device = registry.get("ventilator-01")
    assert device.operational_state == OperationalState.OFF
    assert device.network_state == "offline"


@pytest.mark.parametrize(
    "action",
    [
        ResponseActionCategory.BLOCK_TRAFFIC,
        ResponseActionCategory.RESTRICT_COMMUNICATION,
        ResponseActionCategory.ISOLATE_NON_CRITICAL,
        ResponseActionCategory.ISOLATE_CRITICAL,
        ResponseActionCategory.QUARANTINE_SEGMENT,
    ],
)
def test_isolation_family_actions_isolate_the_device(orchestrator, registry, action):
    decision = _decision("incident-pump", action, False)
    orchestrator.execute(decision)

    device = registry.get("pump-01")
    assert device.operational_state == OperationalState.ISOLATED
    assert device.network_state == "isolated"


def test_restart_service_resets_device_to_idle_and_connected(orchestrator, registry):
    device = registry.get("pump-01")
    device.isolate()
    assert device.operational_state == OperationalState.ISOLATED

    decision = _decision("incident-pump", ResponseActionCategory.RESTART_SERVICE, False)
    orchestrator.execute(decision)

    assert device.operational_state == OperationalState.IDLE
    assert device.network_state == "connected"


@pytest.mark.parametrize(
    "action",
    [
        ResponseActionCategory.REVOKE_SESSION,
        ResponseActionCategory.ROTATE_CREDENTIALS,
        ResponseActionCategory.ACTIVATE_BACKUP,
        ResponseActionCategory.FAILOVER,
    ],
)
def test_actions_with_no_simulator_mechanism_raise_not_implemented(orchestrator, action):
    decision = _decision("incident-pump", action, False)

    with pytest.raises(NotImplementedError, match=action.value):
        orchestrator.execute(decision)
