"""Incident intelligence tests: lifecycle, correlation, evidence, attribution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    AssertionClass,
    AttackType,
    DetectorKind,
    EventKind,
    EvidenceKind,
    IncidentState,
    RecoveryOutcome,
    ResponseActionType,
    ResponseState,
    Severity,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    AgentFinding,
    AgentRunRecord,
    DetectionResult,
    EvidenceRef,
    NormalisedEvent,
    RecoveryCheck,
    RecoveryResult,
    ResponseCandidate,
    ResponseRecord,
)
from incident import (
    IllegalTransition,
    IncidentService,
    InMemoryIncidentRepository,
    can_transition,
    validate_machine,
)
from incident.lifecycle import TERMINAL_STATES, TRANSITIONS, reachable_from

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


class SteppingClock(Clock):
    """Advances a fixed step per call, so ordering is deterministic."""

    def __init__(self, start: datetime = T0, step: float = 1.0) -> None:
        self._t = start
        self._step = timedelta(seconds=step)

    def now(self) -> datetime:
        self._t += self._step
        return self._t


@pytest.fixture
def service() -> IncidentService:
    return IncidentService(
        repository=InMemoryIncidentRepository(),
        ids=IdFactory(deterministic=True),
        clock=SteppingClock(),
    )


def _detection(
    device_id: str = "VENT-1",
    attack: AttackType = AttackType.MALICIOUS_COMMAND,
    confidence: float = 0.9,
    severity: Severity = Severity.HIGH,
    offset: float = 0.0,
) -> DetectionResult:
    return DetectionResult(
        detector_name="test_detector",
        detector_kind=DetectorKind.SUPERVISED_CLASSIFIER,
        model_version="v1",
        timestamp=T0 + timedelta(seconds=offset),
        device_id=device_id,
        is_attack=True,
        attack_type=attack,
        confidence=confidence,
        severity=severity,
    )


def _events(n: int = 3, source_ip: str = "10.66.6.66") -> list[NormalisedEvent]:
    return [
        NormalisedEvent(
            event_id=f"EVT-{i:06d}",
            timestamp=T0 + timedelta(seconds=i),
            kind=EventKind.NETWORK_FLOW,
            device_id="VENT-1",
            source_ip=source_ip,
            destination_ip="10.0.1.11",
        )
        for i in range(n)
    ]


# ===========================================================================
# Lifecycle
# ===========================================================================
class TestLifecycle:
    def test_machine_is_structurally_valid(self) -> None:
        validate_machine()

    def test_every_state_can_reach_a_terminal_state(self) -> None:
        """Otherwise an incident could be stranded and MTTR undefined."""
        for state in IncidentState:
            if state in TERMINAL_STATES:
                continue
            assert reachable_from(state) & TERMINAL_STATES

    def test_resolved_requires_recovery_or_monitor_only(self) -> None:
        """The closed loop must not be short-circuitable."""
        into_resolved = {s for s, t in TRANSITIONS.items() if IncidentState.RESOLVED in t}
        assert into_resolved == {IncidentState.RECOVERING, IncidentState.PLANNING}

    def test_terminal_states_are_terminal(self) -> None:
        for state in TERMINAL_STATES:
            assert TRANSITIONS[state] == frozenset()
            check = can_transition(state, IncidentState.INVESTIGATING)
            assert check.allowed is False
            assert "terminal" in check.reason

    def test_illegal_transition_is_rejected(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        with pytest.raises(IllegalTransition, match="not a legal transition"):
            service.transition(inc.incident_id, IncidentState.RESOLVED, "test", "skipping the loop")

    def test_rejection_names_the_legal_options(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        check = can_transition(inc.state, IncidentState.EXECUTING)
        assert "investigating" in check.reason

    def test_full_happy_path(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        path = [
            IncidentState.INVESTIGATING,
            IncidentState.ASSESSED,
            IncidentState.PLANNING,
            IncidentState.AWAITING_APPROVAL,
            IncidentState.APPROVED,
            IncidentState.EXECUTING,
            IncidentState.RECOVERING,
            IncidentState.RESOLVED,
        ]
        for target in path:
            inc = service.transition(inc.incident_id, target, "test", f"-> {target.value}")
        assert inc.state is IncidentState.RESOLVED
        assert inc.resolved_at is not None

    def test_reinvestigation_increments_the_counter(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        for target in (
            IncidentState.INVESTIGATING,
            IncidentState.ASSESSED,
            IncidentState.PLANNING,
            IncidentState.APPROVED,
            IncidentState.EXECUTING,
            IncidentState.RECOVERING,
        ):
            inc = service.transition(inc.incident_id, target, "t", "step")
        inc = service.transition(
            inc.incident_id, IncidentState.REINVESTIGATING, "t", "recovery failed"
        )
        assert inc.reinvestigation_count == 1
        inc = service.transition(inc.incident_id, IncidentState.PLANNING, "t", "re-plan")
        assert inc.state is IncidentState.PLANNING


# ===========================================================================
# Correlation
# ===========================================================================
class TestCorrelation:
    def test_first_detection_opens_an_incident(self, service) -> None:
        inc, decision = service.ingest_detection(_detection())
        assert decision.is_new_incident
        assert inc.state is IncidentState.DETECTED

    def test_repeat_detection_does_not_open_a_second_incident(self, service) -> None:
        """Otherwise one attack becomes dozens of incidents and MTTD is noise."""
        service.ingest_detection(_detection(offset=0))
        service.ingest_detection(_detection(offset=5))
        service.ingest_detection(_detection(offset=10))
        assert len(service.repository.list_all()) == 1

    def test_multistage_on_one_device_correlates(self, service) -> None:
        service.ingest_detection(_detection(attack=AttackType.ARP_SPOOFING, offset=0))
        _, decision = service.ingest_detection(_detection(attack=AttackType.MITM, offset=30))
        assert not decision.is_new_incident
        assert decision.rule == "same_device_multistage"

    def test_lateral_movement_correlates_across_devices(self, service) -> None:
        """Makes a campaign legible as one intrusion."""
        events = _events(source_ip="10.66.6.66")
        service.ingest_detection(_detection(device_id="WS-1", offset=0), events=events)
        _, decision = service.ingest_detection(
            _detection(device_id="PUMP-1", offset=60), events=events
        )
        assert not decision.is_new_incident
        assert decision.rule == "shared_source_identity"

    def test_unrelated_devices_do_not_correlate(self, service) -> None:
        service.ingest_detection(
            _detection(device_id="WS-1", offset=0), events=_events(source_ip="1.1.1.1")
        )
        _, decision = service.ingest_detection(
            _detection(device_id="PUMP-1", offset=60),
            events=_events(source_ip="2.2.2.2"),
        )
        assert decision.is_new_incident

    def test_stale_detection_opens_a_new_incident(self, service) -> None:
        service.ingest_detection(_detection(offset=0))
        _, decision = service.ingest_detection(_detection(offset=100_000))
        assert decision.is_new_incident

    def test_resolved_incidents_are_not_correlation_targets(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(offset=0))
        for target in (
            IncidentState.INVESTIGATING,
            IncidentState.ASSESSED,
            IncidentState.PLANNING,
            IncidentState.RESOLVED,
        ):
            service.transition(inc.incident_id, target, "t", "step")
        _, decision = service.ingest_detection(_detection(offset=5))
        assert decision.is_new_incident

    def test_device_own_address_is_not_an_attacker_identity(self) -> None:
        """Otherwise every incident on a device correlates into one."""
        from incident.correlation import extract_source_identities

        events = [
            NormalisedEvent(
                event_id="E1",
                timestamp=T0,
                kind=EventKind.NETWORK_FLOW,
                device_id="D1",
                source_ip="10.0.1.11",
                destination_ip="10.0.1.11",
            )
        ]
        assert "10.0.1.11" not in extract_source_identities(events)


# ===========================================================================
# Attribution - the measured bug
# ===========================================================================
class TestAttribution:
    def test_sustained_signal_outweighs_an_early_false_positive(self, service) -> None:
        """The measured failure this logic exists to prevent.

        On `recon_then_pivot` the first detection in the stream was a false
        positive on a device that was never attacked. Because it arrived
        first it founded the incident, and every later true detection was
        correlated into it - so the incident was reported against the wrong
        device with the wrong attack type. One early false positive poisoned
        the attribution of an entire campaign.
        """
        shared = _events(source_ip="10.66.6.66")
        service.ingest_detection(
            _detection(
                device_id="FALSE-POSITIVE",
                attack=AttackType.MITM,
                confidence=0.95,
                offset=0,
            ),
            events=shared,
        )
        for i in range(12):
            service.ingest_detection(
                _detection(
                    device_id="REALLY-ATTACKED",
                    attack=AttackType.MALICIOUS_COMMAND,
                    confidence=0.7,
                    severity=Severity.CRITICAL,
                    offset=20 + i * 5,
                ),
                events=shared,
            )
        incident = service.repository.list_all()[0]
        assert incident.device_id == "REALLY-ATTACKED"
        assert incident.attack_type is AttackType.MALICIOUS_COMMAND

    def test_severity_reflects_the_worst_stage(self, service) -> None:
        service.ingest_detection(
            _detection(attack=AttackType.RECONNAISSANCE, severity=Severity.LOW, offset=0)
        )
        service.ingest_detection(
            _detection(
                attack=AttackType.MALICIOUS_COMMAND,
                severity=Severity.CRITICAL,
                offset=20,
            )
        )
        incident = service.repository.list_all()[0]
        assert incident.severity is Severity.CRITICAL

    def test_observations_accumulate(self, service) -> None:
        for i in range(5):
            service.ingest_detection(_detection(offset=i * 5))
        incident = service.repository.list_all()[0]
        assert len(incident.observations) == 5


# ===========================================================================
# Evidence
# ===========================================================================
class TestEvidence:
    def test_detection_evidence_is_hashed_and_verifies(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(), events=_events())
        assert inc.evidence
        results = service.verify_evidence(inc.incident_id)
        assert all(results.values())

    def test_tampered_evidence_fails_verification(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(), events=_events())
        tampered = inc.evidence[0].model_copy(update={"payload": {"x": "changed"}})
        assert tampered.verify() is False

    def test_identical_evidence_is_not_double_counted(self, service) -> None:
        """The cyber-risk uncertainty term reads the evidence count."""
        inc, _ = service.ingest_detection(_detection(), events=_events())
        before = len(inc.evidence)
        inc = service.add_evidence(inc.incident_id, inc.evidence[0])
        assert len(inc.evidence) == before

    def test_evidence_records_source_identities_for_investigation(self, service) -> None:
        """Evidence may carry identity; the feature matrix may not."""
        inc, _ = service.ingest_detection(_detection(), events=_events(source_ip="203.0.113.5"))
        assert "203.0.113.5" in inc.evidence[0].payload["source_identities"]

    def test_evidence_bundle_hash_changes_with_content(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(), events=_events())
        first = inc.evidence_bundle_hash()
        extra = EvidenceRef(
            evidence_id="EVD-999999",
            kind=EvidenceKind.TELEMETRY_WINDOW,
            created_at=T0,
            produced_by="test",
            payload={"new": True},
        ).with_hash()
        inc = service.add_evidence(inc.incident_id, extra)
        assert inc.evidence_bundle_hash() != first


# ===========================================================================
# Timeline and epistemic discipline
# ===========================================================================
class TestTimeline:
    def test_timeline_is_chronological(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(), events=_events())
        inc = service.transition(inc.incident_id, IncidentState.INVESTIGATING, "t", "investigating")
        entries = service.timeline(inc.incident_id)
        assert entries == sorted(entries, key=lambda e: e.timestamp)

    def test_detection_is_recorded_as_inference_not_fact(self, service) -> None:
        """A detector output is an inference, and must be shown as one."""
        inc, _ = service.ingest_detection(_detection())
        first = inc.timeline[0]
        assert first.assertion_class is AssertionClass.INFERENCE

    def test_transitions_are_recorded_as_observed_fact(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        inc = service.transition(inc.incident_id, IncidentState.INVESTIGATING, "t", "step")
        assert inc.timeline[-1].assertion_class is AssertionClass.OBSERVED_FACT

    def test_agent_findings_keep_their_epistemic_status(self, service) -> None:
        """An agent inference must never be displayed as observed fact."""
        inc, _ = service.ingest_detection(_detection())
        run = AgentRunRecord(
            agent_run_id="AGR-000001",
            incident_id=inc.incident_id,
            agent_role=AgentRole.THREAT_REASONING,
            status=AgentRunStatus.SUCCEEDED,
            started_at=T0,
            finished_at=T0 + timedelta(seconds=2),
            findings=[
                AgentFinding(
                    statement="Flow rate exceeded 14000 pps",
                    assertion_class=AssertionClass.OBSERVED_FACT,
                    confidence=1.0,
                ),
                AgentFinding(
                    statement="This is likely a volumetric DDoS",
                    assertion_class=AssertionClass.INFERENCE,
                    confidence=0.8,
                ),
                AgentFinding(
                    statement="Recommend upstream traffic blocking",
                    assertion_class=AssertionClass.RECOMMENDATION,
                    confidence=0.7,
                ),
            ],
        )
        inc = service.record_agent_run(inc.incident_id, run)
        findings = [e for e in inc.timeline if e.phase == "finding"]
        assert {f.assertion_class for f in findings} == {
            AssertionClass.OBSERVED_FACT,
            AssertionClass.INFERENCE,
            AssertionClass.RECOMMENDATION,
        }

    def test_decision_is_recorded_as_recommendation(self, service) -> None:
        """The policy engine decides executability, not this record."""
        from risk_engine import PatientAwareRiskEngine

        inc, _ = service.ingest_detection(_detection(), events=_events())
        engine = PatientAwareRiskEngine()
        decision = engine.decide(
            incident_id=inc.incident_id,
            decided_at=T0,
            detection=_detection(),
            device=None,
            state=None,
            candidates=[
                ResponseCandidate(action_type=ResponseActionType.MONITOR_ONLY),
                ResponseCandidate(action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC),
            ],
            evidence=inc.evidence,
        )
        inc = service.record_decision(inc.incident_id, decision)
        entry = next(e for e in inc.timeline if e.phase == "decision")
        assert entry.assertion_class is AssertionClass.RECOMMENDATION
        assert inc.decision is not None
        assert inc.cyber_risk is not None


# ===========================================================================
# Exhausted actions - mandated scenario 3
# ===========================================================================
class TestExhaustedActions:
    def _response(self, incident_id: str, action: ResponseActionType, rid: str):
        return ResponseRecord(
            response_id=rid,
            incident_id=incident_id,
            candidate=ResponseCandidate(action_type=action),
            state=ResponseState.EXECUTED,
            proposed_at=T0,
            executed_at=T0 + timedelta(seconds=5),
            execution_succeeded=True,
        )

    def test_failed_action_is_reported_as_exhausted(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        response = self._response(
            inc.incident_id, ResponseActionType.BLOCK_SOURCE_TRAFFIC, "RSP-000001"
        )
        service.record_response(inc.incident_id, response)
        service.record_recovery(
            inc.incident_id,
            RecoveryResult(
                recovery_id="RCV-000001",
                incident_id=inc.incident_id,
                response_id=response.response_id,
                verified_at=T0 + timedelta(seconds=30),
                outcome=RecoveryOutcome.RESIDUAL_RISK,
                checks=[RecoveryCheck(name="anomaly_cleared", passed=False)],
                residual_risk=0.6,
                requires_reinvestigation=True,
            ),
        )
        exhausted = service.exhausted_actions(inc.incident_id)
        assert ResponseActionType.BLOCK_SOURCE_TRAFFIC in exhausted

    def test_recovered_action_is_not_exhausted(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        response = self._response(
            inc.incident_id, ResponseActionType.ROTATE_CREDENTIALS, "RSP-000001"
        )
        service.record_response(inc.incident_id, response)
        service.record_recovery(
            inc.incident_id,
            RecoveryResult(
                recovery_id="RCV-000001",
                incident_id=inc.incident_id,
                response_id=response.response_id,
                verified_at=T0 + timedelta(seconds=30),
                outcome=RecoveryOutcome.RECOVERED,
                checks=[RecoveryCheck(name="anomaly_cleared", passed=True)],
                residual_risk=0.05,
            ),
        )
        assert service.exhausted_actions(inc.incident_id) == []

    def test_response_update_replaces_rather_than_duplicates(self, service) -> None:
        inc, _ = service.ingest_detection(_detection())
        response = self._response(
            inc.incident_id, ResponseActionType.QUARANTINE_DEVICE, "RSP-000001"
        )
        service.record_response(inc.incident_id, response)
        inc = service.record_response(
            inc.incident_id,
            response.model_copy(update={"state": ResponseState.RECOVERED}),
        )
        assert len(inc.responses) == 1
        assert inc.responses[0].state is ResponseState.RECOVERED


class TestRepository:
    def test_unknown_incident_raises(self, service) -> None:
        with pytest.raises(KeyError, match="unknown incident"):
            service.timeline("INC-NOPE")

    def test_list_open_excludes_terminal(self, service) -> None:
        inc, _ = service.ingest_detection(_detection(device_id="D1"))
        service.ingest_detection(_detection(device_id="D2", offset=5))
        for target in (
            IncidentState.INVESTIGATING,
            IncidentState.ASSESSED,
            IncidentState.PLANNING,
            IncidentState.RESOLVED,
        ):
            service.transition(inc.incident_id, target, "t", "step")
        open_ids = {i.incident_id for i in service.repository.list_open()}
        assert inc.incident_id not in open_ids
        assert len(open_ids) == 1
