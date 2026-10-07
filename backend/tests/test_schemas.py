"""Phase 1 schema smoke tests.

These only confirm the contracts in app/schemas/ construct and validate correctly
— there is no business logic to test yet. Real behavioral tests (e.g. the Policy
Engine never autonomously shutting down a patient-dependent ventilator) arrive with
the layers that implement that behavior, starting Phase 5-6.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas import DetectionEvent, DeviceState, RiskScore


def test_detection_event_valid():
    event = DetectionEvent(
        device_id="vent-01",
        attack_type="mitm_injection",
        confidence=0.92,
        severity_hint="critical",
        timestamp=datetime.now(UTC),
        evidence_ref="flow:12345",
    )
    assert event.device_id == "vent-01"
    assert 0.0 <= event.confidence <= 1.0


def test_detection_event_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        DetectionEvent(
            device_id="vent-01",
            attack_type="dos",
            confidence=1.5,  # invalid: must be <= 1.0
            severity_hint="high",
            timestamp=datetime.now(UTC),
            evidence_ref="flow:1",
        )


def test_device_state_patient_dependency_flag():
    device = DeviceState(
        device_id="vent-01",
        device_type="ventilator",
        criticality="high",
        patient_dependency=True,
        operational_state="active",
        network_state="connected",
    )
    assert device.patient_dependency is True
    assert device.criticality == "high"


def test_risk_score_per_action_response_impact():
    score = RiskScore(
        incident_id="inc-1",
        cyber_risk=0.9,
        clinical_risk=0.95,
        response_impact={"shutdown": "critical", "isolate_critical": "high"},
        explanation="Shutdown forced to critical impact regardless of cyber severity.",
    )
    assert score.response_impact["shutdown"] == "critical"
    # Different actions on the same device must be allowed to carry different impact.
    assert score.response_impact["shutdown"] != score.response_impact["isolate_critical"]
