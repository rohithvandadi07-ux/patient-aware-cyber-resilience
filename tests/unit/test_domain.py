"""Domain-layer contract tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    EvidenceKind,
    PatientDependencyLevel,
    ResponseActionType,
    RiskBand,
)
from backend.app.domain.ids import FixedClock, IdFactory, canonical_hash
from backend.app.domain.models import (
    ClinicalRiskResult,
    CyberRiskResult,
    EvidenceRef,
    Incident,
    PatientAwareDecision,
    ResponseImpactResult,
    SyntheticPatientContext,
)

pytestmark = pytest.mark.unit


class TestIdentifiers:
    def test_deterministic_ids_are_sequential(self) -> None:
        f = IdFactory(deterministic=True)
        assert f.incident() == "INC-000001"
        assert f.incident() == "INC-000002"
        assert f.response() == "RSP-000001"

    def test_non_deterministic_ids_are_unique(self) -> None:
        f = IdFactory(deterministic=False)
        assert len({f.incident() for _ in range(200)}) == 200

    def test_fixed_clock_advances_predictably(self) -> None:
        c = FixedClock(start=datetime(2026, 1, 1, tzinfo=UTC), step_seconds=5.0)
        assert (c.now() - c.peek()).total_seconds() == 0.0
        assert (c.now() - c.peek()).total_seconds() == 5.0

    def test_canonical_hash_is_key_order_independent(self) -> None:
        assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})

    def test_canonical_hash_detects_change(self) -> None:
        assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})


class TestSyntheticPatientGuard:
    def test_accepts_synthetic_reference(self) -> None:
        p = SyntheticPatientContext(patient_ref="SYN-PT-0001")
        assert p.synthetic is True

    @pytest.mark.parametrize("bad", ["PT-0001", "REAL-123", "MRN-99887", ""])
    def test_rejects_non_synthetic_reference(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            SyntheticPatientContext(patient_ref=bad)


class TestEvidenceIntegrity:
    def _evidence(self, payload: dict) -> EvidenceRef:
        return EvidenceRef(
            evidence_id="EVD-000001",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
            produced_by="test",
            payload=payload,
        ).with_hash()

    def test_hash_verifies(self) -> None:
        assert self._evidence({"x": 1}).verify() is True

    def test_tampering_is_detected(self) -> None:
        ev = self._evidence({"x": 1})
        tampered = ev.model_copy(update={"payload": {"x": 999}})
        assert tampered.verify() is False

    def test_unhashed_evidence_does_not_verify(self) -> None:
        ev = EvidenceRef(
            evidence_id="EVD-1",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
            produced_by="test",
        )
        assert ev.verify() is False


class TestRiskBanding:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.00, RiskBand.NEGLIGIBLE),
            (0.14, RiskBand.NEGLIGIBLE),
            (0.20, RiskBand.LOW),
            (0.45, RiskBand.MODERATE),
            (0.70, RiskBand.HIGH),
            (0.95, RiskBand.SEVERE),
        ],
    )
    def test_bands(self, score: float, expected: RiskBand) -> None:
        assert CyberRiskResult(score=score).band is expected

    def test_score_is_bounded(self) -> None:
        with pytest.raises(ValidationError):
            CyberRiskResult(score=1.5)
        with pytest.raises(ValidationError):
            CyberRiskResult(score=-0.1)


class TestResponseImpact:
    def test_net_benefit(self) -> None:
        r = ResponseImpactResult(
            action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            security_benefit=0.8,
            clinical_impact=0.1,
        )
        assert r.net_benefit == pytest.approx(0.7)

    def test_unsafe_response_has_negative_net_benefit(self) -> None:
        r = ResponseImpactResult(
            action_type=ResponseActionType.SHUTDOWN_DEVICE,
            security_benefit=0.95,
            clinical_impact=1.0,
        )
        assert r.net_benefit < 0


class TestProvenanceHygiene:
    def test_ledger_payload_excludes_bulk_and_patient_data(self) -> None:
        from backend.app.domain.enums import ProvenanceEventType
        from backend.app.domain.models import ProvenanceRecord

        rec = ProvenanceRecord(
            provenance_id="PRV-000001",
            event_type=ProvenanceEventType.INCIDENT_RECORDED,
            incident_id="INC-000001",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            evidence_hash="deadbeef",
        )
        payload = rec.payload_for_ledger()
        for forbidden in ("payload", "patient", "telemetry"):
            assert forbidden not in payload
        assert payload["evidence_hash"] == "deadbeef"


class TestIncidentAggregate:
    def test_detection_latency_and_resolution_time(self) -> None:
        t0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
        inc = Incident(
            incident_id="INC-000001",
            created_at=t0,
            updated_at=t0,
            attack_started_at=t0,
            detected_at=t0.replace(second=12),
            resolved_at=t0.replace(minute=3),
        )
        assert inc.detection_latency_seconds == pytest.approx(12.0)
        assert inc.time_to_resolution_seconds == pytest.approx(168.0)

    def test_missing_timestamps_yield_none(self) -> None:
        t0 = datetime(2026, 1, 1, tzinfo=UTC)
        inc = Incident(incident_id="INC-1", created_at=t0, updated_at=t0)
        assert inc.detection_latency_seconds is None
        assert inc.time_to_resolution_seconds is None


class TestDecisionCounterfactual:
    def test_divergence_is_recordable(self) -> None:
        t0 = datetime(2026, 1, 1, tzinfo=UTC)
        d = PatientAwareDecision(
            incident_id="INC-000001",
            decided_at=t0,
            cyber_risk=CyberRiskResult(score=0.9),
            clinical_risk=ClinicalRiskResult(
                score=0.95,
                life_support_involved=True,
                patient_dependency=PatientDependencyLevel.LIFE_CRITICAL,
            ),
            selected_action=ResponseActionType.ROTATE_CREDENTIALS,
            cyber_only_action=ResponseActionType.SHUTDOWN_DEVICE,
            diverged_from_cyber_only=True,
            divergence_reason="shutdown would interrupt life-sustaining therapy",
        )
        assert d.diverged_from_cyber_only is True
        assert d.selected_action is not d.cyber_only_action
        assert d.assertion_class is AssertionClass.RECOMMENDATION
