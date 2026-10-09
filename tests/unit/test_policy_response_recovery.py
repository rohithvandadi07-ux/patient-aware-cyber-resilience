"""Policy, response-orchestration and recovery tests.

The unskippable-policy tests matter most: they assert that no code path
reaches actuation without a permitting verdict, which is the property that
makes "controlled autonomy" more than a label.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.domain.enums import (
    AcuityLevel,
    ApprovalStatus,
    AttackType,
    CriticalityTier,
    DetectorKind,
    DeviceOperationalState,
    DeviceType,
    EvidenceKind,
    ImpactClass,
    PatientDependencyLevel,
    PolicyDecision,
    RecoveryOutcome,
    ResponseActionType,
    ResponseState,
    Severity,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    DetectionResult,
    DeviceProfile,
    DeviceState,
    EvidenceRef,
    ResponseCandidate,
    SyntheticPatientContext,
)
from recovery import RecoveryEngine, RecoveryObservation
from recovery.engine import MECHANISM_SEVERED_BY
from response_engine import (
    IllegalResponseTransition,
    PolicyContext,
    PolicyEngine,
    PolicyValidationError,
    ResponseOrchestrator,
    UnauthorisedExecution,
    validate_response_machine,
)
from response_engine.orchestrator import BLOCKED_STATES, RESPONSE_TRANSITIONS
from risk_engine import PatientAwareRiskEngine

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


class SteppingClock(Clock):
    def __init__(self) -> None:
        self._t = T0

    def now(self) -> datetime:
        self._t += timedelta(seconds=1)
        return self._t


@pytest.fixture(scope="module")
def policy() -> PolicyEngine:
    return PolicyEngine.load()


@pytest.fixture(scope="module")
def engine() -> PatientAwareRiskEngine:
    return PatientAwareRiskEngine()


@pytest.fixture
def orchestrator(policy) -> ResponseOrchestrator:
    calls: list[tuple] = []

    def actuator(action: str, device: str | None, segment: str | None) -> dict:
        calls.append((action, device, segment))
        return {"succeeded": True, "affected_devices": [device] if device else []}

    orch = ResponseOrchestrator(
        policy=policy,
        ids=IdFactory(deterministic=True),
        clock=SteppingClock(),
        actuator=actuator,
    )
    orch.actuator_calls = calls  # type: ignore[attr-defined]
    return orch


def _ventilator(redundant: bool = False) -> DeviceProfile:
    return DeviceProfile(
        device_id="VENT-TEST-01",
        device_type=DeviceType.VENTILATOR,
        criticality=CriticalityTier.LIFE_SUSTAINING,
        life_support_relevant=True,
        has_redundant_peer=redundant,
        supports_safe_failover=redundant,
        acceptable_interruption_seconds=15.0 if redundant else 0.0,
        patient=SyntheticPatientContext(
            patient_ref="SYN-PT-TEST",
            acuity=AcuityLevel.CRITICAL,
            dependency=PatientDependencyLevel.LIFE_CRITICAL,
            on_life_support=True,
            tolerable_interruption_minutes=0.0,
        ),
    )


def _workstation() -> DeviceProfile:
    return DeviceProfile(
        device_id="WS-TEST-01",
        device_type=DeviceType.WORKSTATION,
        criticality=CriticalityTier.NON_CLINICAL,
        acceptable_interruption_seconds=3600.0,
    )


def _state(device_id: str, delivering: bool = True, faults: list[str] | None = None):
    return DeviceState(
        device_id=device_id,
        timestamp=T0,
        operational_state=DeviceOperationalState.ACTIVE,
        delivering_therapy=delivering,
        fault_codes=faults or [],
    )


def _risks(engine, device, state, attack=AttackType.MALICIOUS_COMMAND):
    detection = DetectionResult(
        detector_name="test",
        detector_kind=DetectorKind.SUPERVISED_CLASSIFIER,
        timestamp=T0,
        device_id=device.device_id,
        is_attack=True,
        attack_type=attack,
        confidence=0.9,
        severity=Severity.HIGH,
    )
    evidence = [
        EvidenceRef(
            evidence_id=f"EVD-{i}",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=T0,
            produced_by="test",
        ).with_hash()
        for i in range(4)
    ]
    return engine.cyber_risk(detection, evidence), engine.clinical_risk(device, state)


def _ctx(engine, policy, device, state, action, attack=AttackType.MALICIOUS_COMMAND, **kwargs):
    cyber, clinical = _risks(engine, device, state, attack)
    impact = engine.response_impact(
        ResponseCandidate(action_type=action, target_device_id=device.device_id),
        device,
        state,
        clinical,
        attack,
    )
    return PolicyContext(
        action=action,
        impact=impact,
        cyber_risk=cyber,
        clinical_risk=clinical,
        device=device,
        state=state,
        **kwargs,
    )


# ===========================================================================
# Policy structure
# ===========================================================================
class TestPolicyStructure:
    def test_default_policy_loads(self, policy) -> None:
        assert policy.policy_version
        assert policy.fingerprint()
        assert len(policy.rules) > 5

    def test_policy_is_total(self, policy) -> None:
        """Some rule must match every input, or a verdict is undefined."""
        assert policy.rules[-1].conditions == {}

    def test_fallthrough_is_not_permissive(self, policy) -> None:
        """A policy whose default is 'allow' is not a safety policy."""
        assert policy.rules[-1].decision is not PolicyDecision.AUTO_ALLOWED

    def test_unsafe_is_denied_before_any_allow(self, policy) -> None:
        first_allow = next(
            i for i, r in enumerate(policy.rules) if r.decision is PolicyDecision.AUTO_ALLOWED
        )
        denies_unsafe = [
            r
            for r in policy.rules[:first_allow]
            if r.decision is PolicyDecision.DENIED
            and "unsafe" in {str(v) for v in r.conditions.get("impact_class", [])}
        ]
        assert denies_unsafe

    def test_unknown_condition_is_rejected_at_load(self) -> None:
        with pytest.raises(PolicyValidationError, match="unknown conditions"):
            PolicyEngine.from_dict(
                {
                    "policy_version": "t",
                    "rules": [
                        {"name": "r", "decision": "denied", "when": {"phase_of_moon": "full"}},
                        {"name": "d", "decision": "approval_required", "when": {}},
                    ],
                }
            )

    def test_permissive_fallthrough_is_rejected_at_load(self) -> None:
        with pytest.raises(PolicyValidationError, match="not a safety policy"):
            PolicyEngine.from_dict(
                {
                    "policy_version": "t",
                    "rules": [{"name": "d", "decision": "auto_allowed", "when": {}}],
                }
            )

    def test_non_total_policy_is_rejected_at_load(self) -> None:
        with pytest.raises(PolicyValidationError, match="catch-all"):
            PolicyEngine.from_dict(
                {
                    "policy_version": "t",
                    "rules": [
                        {"name": "r", "decision": "denied", "when": {"impact_class": ["unsafe"]}}
                    ],
                }
            )

    def test_duplicate_rule_names_rejected(self) -> None:
        with pytest.raises(PolicyValidationError, match="duplicate"):
            PolicyEngine.from_dict(
                {
                    "policy_version": "t",
                    "rules": [
                        {"name": "x", "decision": "denied", "when": {"impact_class": ["unsafe"]}},
                        {"name": "x", "decision": "approval_required", "when": {}},
                    ],
                }
            )

    def test_missing_profile_is_refused(self) -> None:
        with pytest.raises(FileNotFoundError, match="cannot be"):
            PolicyEngine.load("configs/nope.yaml")

    def test_unanswered_approval_defaults_to_denial(self, policy) -> None:
        """An unanswered request must never become consent."""
        assert policy.deny_on_timeout is True


# ===========================================================================
# Policy verdicts
# ===========================================================================
class TestPolicyVerdicts:
    def test_unsafe_action_is_denied_not_escalated(self, engine, policy) -> None:
        """Denial is not escalation.

        Asking a human to authorise what the system judged unsafe converts a
        safety judgement into a liability transfer.
        """
        vent = _ventilator()
        ctx = _ctx(engine, policy, vent, _state(vent.device_id), ResponseActionType.SHUTDOWN_DEVICE)
        assert ctx.impact.impact_class is ImpactClass.UNSAFE
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.DENIED
        assert verdict.decision is not PolicyDecision.APPROVAL_REQUIRED

    def test_low_impact_on_noncritical_is_autonomous(self, engine, policy) -> None:
        ws = _workstation()
        ctx = _ctx(
            engine,
            policy,
            ws,
            _state(ws.device_id, delivering=False),
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.AUTO_ALLOWED

    def test_high_clinical_risk_requires_approval(self, engine, policy) -> None:
        vent = _ventilator()
        ctx = _ctx(
            engine, policy, vent, _state(vent.device_id), ResponseActionType.ROTATE_CREDENTIALS
        )
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.APPROVAL_REQUIRED
        assert verdict.required_role == "clinical_approver"

    def test_monitoring_is_always_autonomous(self, engine, policy) -> None:
        vent = _ventilator()
        ctx = _ctx(engine, policy, vent, _state(vent.device_id), ResponseActionType.MONITOR_ONLY)
        assert policy.evaluate(ctx).decision is PolicyDecision.AUTO_ALLOWED

    def test_already_attempted_is_denied(self, engine, policy) -> None:
        ws = _workstation()
        ctx = _ctx(
            engine,
            policy,
            ws,
            _state(ws.device_id, delivering=False),
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            AttackType.DOS,
            already_attempted=True,
        )
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.DENIED
        assert "already" in verdict.matched_rule

    def test_irreversible_action_requires_approval(self, engine, policy) -> None:
        ws = _workstation()
        ctx = _ctx(
            engine,
            policy,
            ws,
            _state(ws.device_id, delivering=False),
            ResponseActionType.SHUTDOWN_DEVICE,
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.APPROVAL_REQUIRED

    def test_every_verdict_names_its_rule(self, engine, policy) -> None:
        """Autonomous action must be attributable to a published rule."""
        for device, delivering in ((_ventilator(), True), (_workstation(), False)):
            for action in ResponseActionType:
                ctx = _ctx(engine, policy, device, _state(device.device_id, delivering), action)
                verdict = policy.evaluate(ctx)
                assert verdict.matched_rule, f"no rule recorded for {action.value}"
                assert verdict.reasons

    def test_policy_is_total_in_practice(self, engine, policy) -> None:
        for device, delivering in ((_ventilator(), True), (_workstation(), False)):
            for action in ResponseActionType:
                for attack in AttackType:
                    ctx = _ctx(
                        engine, policy, device, _state(device.device_id, delivering), action, attack
                    )
                    assert policy.evaluate(ctx).decision in set(PolicyDecision)

    def test_policy_is_deterministic(self, engine, policy) -> None:
        vent = _ventilator()
        ctx = _ctx(
            engine, policy, vent, _state(vent.device_id), ResponseActionType.QUARANTINE_DEVICE
        )
        a, b = policy.evaluate(ctx), policy.evaluate(ctx)
        assert a.decision is b.decision
        assert a.matched_rule == b.matched_rule

    def test_autonomy_budget_escalates_a_nonconverging_loop(self, engine, policy) -> None:
        ws = _workstation()
        ctx = _ctx(
            engine,
            policy,
            ws,
            _state(ws.device_id, delivering=False),
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            AttackType.DOS,
            autonomous_actions_taken=99,
        )
        verdict = policy.evaluate(ctx)
        assert verdict.decision is PolicyDecision.APPROVAL_REQUIRED
        assert "budget_exhausted" in verdict.matched_rule

    def test_disabled_autonomy_requires_approval_for_everything(self, engine, policy) -> None:
        """The 'without controlled autonomy' ablation."""
        ablated = policy.with_autonomy_disabled()
        ws = _workstation()
        ctx = _ctx(
            engine,
            ablated,
            ws,
            _state(ws.device_id, delivering=False),
            ResponseActionType.MONITOR_ONLY,
        )
        verdict = ablated.evaluate(ctx)
        assert verdict.decision is PolicyDecision.APPROVAL_REQUIRED
        assert verdict.matched_rule == "autonomy_disabled"

    def test_redundancy_changes_the_verdict(self, engine, policy) -> None:
        alone, paired = _ventilator(False), _ventilator(True)
        a = policy.evaluate(
            _ctx(
                engine,
                policy,
                alone,
                _state(alone.device_id),
                ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE,
                AttackType.FIRMWARE_TAMPER,
            )
        )
        b = policy.evaluate(
            _ctx(
                engine,
                policy,
                paired,
                _state(paired.device_id),
                ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE,
                AttackType.FIRMWARE_TAMPER,
            )
        )
        assert a.decision is PolicyDecision.DENIED
        assert b.decision is not PolicyDecision.DENIED


# ===========================================================================
# Response state machine
# ===========================================================================
class TestResponseMachine:
    def test_machine_is_structurally_valid(self) -> None:
        validate_response_machine()

    def test_execution_requires_a_permitting_state(self) -> None:
        into = {s for s, t in RESPONSE_TRANSITIONS.items() if ResponseState.EXECUTING in t}
        assert into == {ResponseState.AUTO_ALLOWED, ResponseState.APPROVED}

    def test_denied_and_rejected_are_terminal(self) -> None:
        for state in BLOCKED_STATES:
            assert RESPONSE_TRANSITIONS[state] == frozenset()

    def test_resolved_requires_recovery(self) -> None:
        """Execution alone must not close a response."""
        into = {s for s, t in RESPONSE_TRANSITIONS.items() if ResponseState.RESOLVED in t}
        assert into == {ResponseState.RECOVERED}

    def test_illegal_transition_raises(self, orchestrator) -> None:
        response = orchestrator.propose(
            "INC-1", ResponseCandidate(action_type=ResponseActionType.MONITOR_ONLY)
        )
        with pytest.raises(IllegalResponseTransition):
            orchestrator._transition(response, ResponseState.EXECUTED, "test")


# ===========================================================================
# Policy cannot be skipped - the central safety property
# ===========================================================================
class TestPolicyIsUnskippable:
    def test_execution_without_evaluation_is_refused(self, orchestrator) -> None:
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.SHUTDOWN_DEVICE, target_device_id="VENT-TEST-01"
            ),
        )
        with pytest.raises(UnauthorisedExecution, match="has not been evaluated"):
            orchestrator.execute(response)
        assert orchestrator.actuator_calls == []

    def test_denied_action_cannot_execute(self, engine, orchestrator) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        cyber, clinical = _risks(engine, vent, state)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.SHUTDOWN_DEVICE),
            vent,
            state,
            clinical,
            AttackType.MALICIOUS_COMMAND,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.SHUTDOWN_DEVICE, target_device_id=vent.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, vent, state)
        assert response.state is ResponseState.DENIED
        with pytest.raises(UnauthorisedExecution, match="(?i)denied"):
            orchestrator.execute(response)
        assert orchestrator.actuator_calls == []

    def test_pending_approval_cannot_execute(self, engine, orchestrator) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        cyber, clinical = _risks(engine, vent, state)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.ROTATE_CREDENTIALS),
            vent,
            state,
            clinical,
            AttackType.MALICIOUS_COMMAND,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.ROTATE_CREDENTIALS, target_device_id=vent.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, vent, state)
        assert response.state is ResponseState.APPROVAL_REQUIRED
        with pytest.raises(UnauthorisedExecution, match="(?i)approval is pending"):
            orchestrator.execute(response)
        assert orchestrator.actuator_calls == []

    def test_rejected_approval_cannot_execute(self, engine, orchestrator) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        cyber, clinical = _risks(engine, vent, state)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.ROTATE_CREDENTIALS),
            vent,
            state,
            clinical,
            AttackType.MALICIOUS_COMMAND,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.ROTATE_CREDENTIALS, target_device_id=vent.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, vent, state)
        response = orchestrator.resolve_approval(
            response, ApprovalStatus.REJECTED, "clinician", "too risky now"
        )
        assert response.state is ResponseState.REJECTED
        with pytest.raises(UnauthorisedExecution):
            orchestrator.execute(response)
        assert orchestrator.actuator_calls == []

    def test_expired_approval_cannot_execute(self, engine, orchestrator) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        cyber, clinical = _risks(engine, vent, state)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.ROTATE_CREDENTIALS),
            vent,
            state,
            clinical,
            AttackType.MALICIOUS_COMMAND,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.ROTATE_CREDENTIALS, target_device_id=vent.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, vent, state)
        response = orchestrator.expire_approval(response)
        assert response.approval.status is ApprovalStatus.EXPIRED
        assert response.state is ResponseState.REJECTED
        with pytest.raises(UnauthorisedExecution):
            orchestrator.execute(response)

    def test_auto_allowed_action_executes(self, engine, orchestrator) -> None:
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        cyber, clinical = _risks(engine, ws, state, AttackType.RANSOMWARE_BEHAVIOUR)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.QUARANTINE_DEVICE),
            ws,
            state,
            clinical,
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.QUARANTINE_DEVICE, target_device_id=ws.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, ws, state)
        assert response.state is ResponseState.AUTO_ALLOWED
        response = orchestrator.execute(response)
        assert response.state is ResponseState.EXECUTED
        assert orchestrator.actuator_calls

    def test_approved_action_executes(self, engine, orchestrator) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        cyber, clinical = _risks(engine, vent, state)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.ROTATE_CREDENTIALS),
            vent,
            state,
            clinical,
            AttackType.MALICIOUS_COMMAND,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.ROTATE_CREDENTIALS, target_device_id=vent.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, vent, state)
        response = orchestrator.resolve_approval(
            response, ApprovalStatus.APPROVED, "clinician-01", "mechanism-appropriate"
        )
        response = orchestrator.execute(response)
        assert response.state is ResponseState.EXECUTED
        assert response.approval.approver == "clinician-01"

    def test_actuator_failure_is_recorded(self, policy, engine) -> None:
        def failing(action: str, device: str | None, segment: str | None) -> dict:
            raise RuntimeError("device unreachable")

        orch = ResponseOrchestrator(
            policy=policy,
            ids=IdFactory(deterministic=True),
            clock=SteppingClock(),
            actuator=failing,
        )
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        cyber, clinical = _risks(engine, ws, state, AttackType.DOS)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC),
            ws,
            state,
            clinical,
            AttackType.DOS,
        )
        response = orch.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC, target_device_id=ws.device_id
            ),
        )
        response = orch.evaluate(response, impact, cyber, clinical, ws, state)
        response = orch.execute(response)
        assert response.state is ResponseState.FAILED
        assert "device unreachable" in response.execution_detail

    def test_transitions_are_fully_audited(self, engine, orchestrator) -> None:
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        cyber, clinical = _risks(engine, ws, state, AttackType.DOS)
        impact = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC),
            ws,
            state,
            clinical,
            AttackType.DOS,
        )
        response = orchestrator.propose(
            "INC-1",
            ResponseCandidate(
                action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC, target_device_id=ws.device_id
            ),
        )
        response = orchestrator.evaluate(response, impact, cyber, clinical, ws, state)
        response = orchestrator.execute(response)
        states = [t["to"] for t in response.transitions]
        assert states[0] == "proposed"
        assert "policy_check" in states
        assert states[-1] == "executed"
        for transition in response.transitions:
            assert transition["by"], "every transition must record its actor"


# ===========================================================================
# Recovery verification
# ===========================================================================
class TestRecovery:
    def _recovery(self) -> RecoveryEngine:
        return RecoveryEngine(ids=IdFactory(deterministic=True), clock=SteppingClock())

    def _executed(self, action: ResponseActionType, succeeded: bool = True):
        from backend.app.domain.models import ResponseRecord

        return ResponseRecord(
            response_id="RSP-000001",
            incident_id="INC-000001",
            candidate=ResponseCandidate(action_type=action, target_device_id="D-1"),
            state=ResponseState.EXECUTED,
            proposed_at=T0,
            executed_at=T0 + timedelta(seconds=2),
            execution_succeeded=succeeded,
            execution_detail="ok" if succeeded else "failed",
        )

    def test_execution_alone_is_not_recovery(self) -> None:
        """The error this engine exists to prevent."""
        response = self._executed(ResponseActionType.BLOCK_SOURCE_TRAFFIC)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=True,
            active_attack_types=frozenset({AttackType.UNAUTHORIZED_ACCESS}),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert result.outcome is not RecoveryOutcome.RECOVERED
        assert result.requires_reinvestigation is True

    def test_traffic_blocking_does_not_sever_a_valid_session(self) -> None:
        """The asymmetry mandated scenario 3 depends on."""
        severing = MECHANISM_SEVERED_BY[AttackType.UNAUTHORIZED_ACCESS]
        assert ResponseActionType.BLOCK_SOURCE_TRAFFIC not in severing
        assert ResponseActionType.REVOKE_SESSION in severing
        assert ResponseActionType.ROTATE_CREDENTIALS in severing

    def test_mechanism_appropriate_action_recovers(self) -> None:
        response = self._executed(ResponseActionType.ROTATE_CREDENTIALS)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert result.outcome is RecoveryOutcome.RECOVERED
        assert result.requires_reinvestigation is False
        assert result.residual_risk < 0.1

    def test_response_that_breaks_the_device_has_not_succeeded(self) -> None:
        """Containment that harms the device is not recovery."""
        response = self._executed(ResponseActionType.QUARANTINE_DEVICE)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False, faults=["THERAPY_HALTED"]),
            device_profile=_ventilator(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            pre_response_state=_state("D-1", delivering=True),
        )
        result = self._recovery().verify("INC-000001", response, obs, AttackType.MALICIOUS_COMMAND)
        assert result.outcome is RecoveryOutcome.NEW_FAULT_INTRODUCED
        assert result.requires_reinvestigation is True

    def test_therapy_continuity_is_checked_for_a_dependent_patient(self) -> None:
        response = self._executed(ResponseActionType.ROTATE_CREDENTIALS)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_ventilator(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify("INC-000001", response, obs, AttackType.MALICIOUS_COMMAND)
        failed = {c.name for c in result.checks if not c.passed}
        assert "therapy_continuity" in failed

    def test_failed_execution_is_not_recovery(self) -> None:
        response = self._executed(ResponseActionType.ROTATE_CREDENTIALS, succeeded=False)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert result.outcome is RecoveryOutcome.FAILED

    def test_still_active_attack_dominates_residual_risk(self) -> None:
        response = self._executed(ResponseActionType.ROTATE_CREDENTIALS)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=False,
            active_attack_types=frozenset({AttackType.UNAUTHORIZED_ACCESS}),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert result.residual_risk >= 0.6
        assert any(f.name == "attack_still_active" for f in result.residual_factors)

    def test_failed_action_is_added_to_exhausted(self) -> None:
        response = self._executed(ResponseActionType.BLOCK_SOURCE_TRAFFIC)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=True,
            active_attack_types=frozenset({AttackType.UNAUTHORIZED_ACCESS}),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert ResponseActionType.BLOCK_SOURCE_TRAFFIC in result.exhausted_actions

    def test_recovered_action_is_not_exhausted(self) -> None:
        response = self._executed(ResponseActionType.ROTATE_CREDENTIALS)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        assert result.exhausted_actions == []

    def test_every_failed_check_is_explained(self) -> None:
        response = self._executed(ResponseActionType.BLOCK_SOURCE_TRAFFIC)
        obs = RecoveryObservation(
            device_state=None,
            device_profile=None,
            detector_still_flagging=True,
            active_attack_types=frozenset({AttackType.UNAUTHORIZED_ACCESS}),
        )
        result = self._recovery().verify(
            "INC-000001", response, obs, AttackType.UNAUTHORIZED_ACCESS
        )
        for check in result.checks:
            assert check.expected
            assert check.observed
        assert result.explanation
        assert "Failed:" in result.explanation

    def test_network_containment_uses_baseline(self) -> None:
        response = self._executed(ResponseActionType.BLOCK_SOURCE_TRAFFIC)
        obs = RecoveryObservation(
            device_state=_state("D-1", delivering=False),
            device_profile=_workstation(),
            detector_still_flagging=False,
            active_attack_types=frozenset(),
            post_response_flow_rate=50_000.0,
            baseline_flow_rate=800.0,
            pre_response_state=_state("D-1", delivering=False),
        )
        result = self._recovery().verify("INC-000001", response, obs, AttackType.DDOS)
        failed = {c.name for c in result.checks if not c.passed}
        assert "network_contained" in failed


# ===========================================================================
# The simulator must agree with the recovery engine
# ===========================================================================
class TestSimulatorAgreesWithRecoveryModel:
    """A measured defect: the two layers disagreed.

    The recovery engine lists ROTATE_CREDENTIALS as severing
    UNAUTHORIZED_ACCESS, but the simulator's infusion pump cleared only
    MALICIOUS_COMMAND on rotation, leaving the session installed. Recovery
    then correctly reported the attack as still active and the loop never
    converged - which looked like a recovery-engine bug but was a simulator
    gap. Session invalidation now lives in the device base class.
    """

    @pytest.mark.parametrize(
        "attack",
        [
            AttackType.UNAUTHORIZED_ACCESS,
            AttackType.MALICIOUS_COMMAND,
            AttackType.SPOOFED_TELEMETRY,
            AttackType.CREDENTIAL_BRUTE_FORCE,
        ],
    )
    def test_credential_rotation_clears_session_based_attacks(self, attack: AttackType) -> None:
        from iomt_simulator.base import AttackEffect, ControlAction
        from iomt_simulator.hospital import SmartHospital
        from iomt_simulator.scenarios.library import get_scenario

        hospital = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        hospital.run(20)
        for device_id in ("PUMP-ICU-01", "VENT-ICU-01", "ECG-ICU-01", "WS-NURSE-01"):
            device = hospital.devices[device_id]
            device.install_attack(AttackEffect(attack_type=attack, started_at=hospital.now))
            assert any(a.attack_type is attack for a in device.attacks)
            device.apply_control(ControlAction(name="rotate_credentials", applied_at=hospital.now))
            assert not any(a.attack_type is attack for a in device.attacks), (
                f"{device_id}: credential rotation left {attack.value} installed, "
                "contradicting recovery.engine.MECHANISM_SEVERED_BY"
            )

    def test_traffic_blocking_leaves_a_session_installed(self) -> None:
        """The honest asymmetry, asserted in the simulator too."""
        from iomt_simulator.hospital import SmartHospital
        from iomt_simulator.scenarios.library import get_scenario

        hospital = SmartHospital(
            scenario=get_scenario("s3_recovery_failure"),
            ids=IdFactory(deterministic=True),
        )
        hospital.run(80)
        pump = hospital.devices["PUMP-ICU-01"]
        assert any(a.attack_type is AttackType.UNAUTHORIZED_ACCESS for a in pump.attacks)
        hospital.apply_response("block_source_traffic", device_id="PUMP-ICU-01")
        assert any(a.attack_type is AttackType.UNAUTHORIZED_ACCESS for a in pump.attacks), (
            "traffic blocking must not clear a valid-session attack"
        )

    def test_every_severing_action_is_actuatable(self) -> None:
        """A listed severing action must exist in the simulator's action set."""
        from iomt_simulator.hospital import SmartHospital
        from iomt_simulator.scenarios.library import get_scenario

        hospital = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        hospital.run(5)
        for actions in MECHANISM_SEVERED_BY.values():
            for action in actions:
                result = hospital.apply_response(
                    action.value, device_id="WS-NURSE-01", segment="vlan-admin"
                )
                assert "action" in result, f"{action.value} is not actuatable"
