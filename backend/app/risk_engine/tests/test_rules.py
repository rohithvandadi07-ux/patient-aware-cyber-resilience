import pytest

from app.risk_engine.rules import score_clinical_risk, score_cyber_risk, score_response_impact
from app.schemas.agents import ClinicalContext, ThreatAssessment
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    ResponseActionCategory,
)


def _threat(severity: ImpactLevel, confidence: float) -> ThreatAssessment:
    return ThreatAssessment(
        incident_id="incident-1",
        attack_type=AttackCategory.SPOOFING,
        severity=severity,
        confidence=confidence,
        propagation_risk=ImpactLevel.LOW,
        reasoning_summary="test",
    )


def _context(
    criticality: DeviceCriticality, patient_dependency: bool, impact: ImpactLevel = ImpactLevel.MEDIUM
) -> ClinicalContext:
    return ClinicalContext(
        incident_id="incident-1",
        device_criticality=criticality,
        patient_dependency=patient_dependency,
        clinical_impact_level=impact,
        safety_constraints=[],
    )


# --- score_cyber_risk ---------------------------------------------------


@pytest.mark.parametrize(
    "severity,confidence",
    [
        (ImpactLevel.LOW, 1.0),
        (ImpactLevel.MEDIUM, 1.0),
        (ImpactLevel.HIGH, 1.0),
        (ImpactLevel.CRITICAL, 1.0),
    ],
)
def test_score_cyber_risk_is_in_valid_range(severity, confidence):
    score, _ = score_cyber_risk(_threat(severity, confidence))
    assert 0.0 <= score <= 1.0


def test_score_cyber_risk_increases_monotonically_with_severity_at_full_confidence():
    severities = (ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL)
    scores = [score_cyber_risk(_threat(s, 1.0))[0] for s in severities]
    assert scores == sorted(scores)
    assert len(set(scores)) == 4


def test_score_cyber_risk_scales_down_with_lower_confidence():
    high_confidence, _ = score_cyber_risk(_threat(ImpactLevel.HIGH, 1.0))
    low_confidence, _ = score_cyber_risk(_threat(ImpactLevel.HIGH, 0.0))
    assert low_confidence < high_confidence


def test_score_cyber_risk_confidence_floor_keeps_critical_above_low_at_full_confidence():
    # Even at zero confidence, a CRITICAL-severity assessment must not drop
    # below a full-confidence LOW-severity assessment -- severity sets a
    # floor that confidence scaling cannot erase entirely.
    critical_zero_confidence, _ = score_cyber_risk(_threat(ImpactLevel.CRITICAL, 0.0))
    low_full_confidence, _ = score_cyber_risk(_threat(ImpactLevel.LOW, 1.0))
    assert critical_zero_confidence > low_full_confidence


def test_score_cyber_risk_explanation_names_severity_and_confidence():
    _, explanation = score_cyber_risk(_threat(ImpactLevel.HIGH, 0.75))
    assert "high" in explanation
    assert "0.75" in explanation


# --- score_clinical_risk -------------------------------------------------


@pytest.mark.parametrize(
    "criticality", [DeviceCriticality.LOW, DeviceCriticality.MEDIUM, DeviceCriticality.HIGH]
)
@pytest.mark.parametrize("patient_dependency", [True, False])
def test_score_clinical_risk_is_in_valid_range(criticality, patient_dependency):
    score, _ = score_clinical_risk(_context(criticality, patient_dependency))
    assert 0.0 <= score <= 1.0


def test_score_clinical_risk_increases_with_criticality_when_not_patient_dependent():
    scores = [
        score_clinical_risk(_context(c, patient_dependency=False))[0]
        for c in (DeviceCriticality.LOW, DeviceCriticality.MEDIUM, DeviceCriticality.HIGH)
    ]
    assert scores == sorted(scores)
    assert len(set(scores)) == 3


def test_score_clinical_risk_patient_dependency_floor_applies_to_low_criticality_device():
    # A LOW-criticality device a patient nonetheless currently depends on
    # must still be floored -- dependency, not criticality alone, is what
    # the floor guards.
    low_criticality_dependent, explanation = score_clinical_risk(
        _context(DeviceCriticality.LOW, patient_dependency=True, impact=ImpactLevel.LOW)
    )
    assert low_criticality_dependent >= 0.55
    assert "floor" in explanation


def test_score_clinical_risk_floor_does_not_apply_when_not_patient_dependent():
    low_criticality_independent, _ = score_clinical_risk(
        _context(DeviceCriticality.LOW, patient_dependency=False, impact=ImpactLevel.LOW)
    )
    assert low_criticality_independent < 0.55


def test_score_clinical_risk_does_not_lower_an_already_high_score_via_floor():
    # HIGH criticality + CRITICAL impact should already exceed the floor on
    # its own -- the floor must never clamp a score *down* to itself.
    score, explanation = score_clinical_risk(
        _context(DeviceCriticality.HIGH, patient_dependency=True, impact=ImpactLevel.CRITICAL)
    )
    assert score > 0.55
    assert "floor applied" not in explanation


def test_score_clinical_risk_higher_impact_level_increases_score_at_same_criticality():
    low_impact, _ = score_clinical_risk(
        _context(DeviceCriticality.MEDIUM, patient_dependency=False, impact=ImpactLevel.LOW)
    )
    critical_impact, _ = score_clinical_risk(
        _context(DeviceCriticality.MEDIUM, patient_dependency=False, impact=ImpactLevel.CRITICAL)
    )
    assert critical_impact > low_impact


# --- score_response_impact -----------------------------------------------


def test_shutdown_on_high_criticality_dependent_device_is_critical_regardless_of_anything_else():
    # The literal Section 12 example rule.
    context = _context(DeviceCriticality.HIGH, patient_dependency=True)
    impact, explanation = score_response_impact(ResponseActionCategory.SHUTDOWN, context)
    assert impact == ImpactLevel.CRITICAL
    assert "forced" in explanation


def test_isolate_critical_on_high_criticality_dependent_device_is_also_critical():
    context = _context(DeviceCriticality.HIGH, patient_dependency=True)
    impact, _ = score_response_impact(ResponseActionCategory.ISOLATE_CRITICAL, context)
    assert impact == ImpactLevel.CRITICAL


def test_shutdown_on_non_dependent_device_is_not_critical():
    context = _context(DeviceCriticality.HIGH, patient_dependency=False)
    impact, _ = score_response_impact(ResponseActionCategory.SHUTDOWN, context)
    assert impact != ImpactLevel.CRITICAL


def test_shutdown_on_patient_dependent_medium_criticality_device_is_high_not_critical():
    # Patient-dependent but NOT high-criticality: the "forced critical" rule
    # requires BOTH high criticality AND patient dependency. Dependency alone
    # on a lower-criticality device should still escalate a severe-disruption
    # action, but to HIGH, not CRITICAL.
    context = _context(DeviceCriticality.MEDIUM, patient_dependency=True)
    impact, explanation = score_response_impact(ResponseActionCategory.SHUTDOWN, context)
    assert impact == ImpactLevel.HIGH
    assert "not forced to critical" in explanation


def test_isolate_non_critical_on_patient_dependent_medium_criticality_device_is_medium():
    # Same dependent-but-not-high-criticality combination, for the
    # moderate-disruption tier this time.
    context = _context(DeviceCriticality.MEDIUM, patient_dependency=True)
    impact, _ = score_response_impact(ResponseActionCategory.ISOLATE_NON_CRITICAL, context)
    assert impact == ImpactLevel.MEDIUM


def test_isolate_non_critical_on_dependent_device_scores_lower_than_shutdown():
    context = _context(DeviceCriticality.HIGH, patient_dependency=True)
    shutdown_impact, _ = score_response_impact(ResponseActionCategory.SHUTDOWN, context)
    isolate_impact, _ = score_response_impact(ResponseActionCategory.ISOLATE_NON_CRITICAL, context)
    impact_order = {ImpactLevel.LOW: 0, ImpactLevel.MEDIUM: 1, ImpactLevel.HIGH: 2, ImpactLevel.CRITICAL: 3}
    assert impact_order[isolate_impact] < impact_order[shutdown_impact]


def test_rotate_credentials_on_dependent_device_is_low_impact():
    context = _context(DeviceCriticality.HIGH, patient_dependency=True)
    impact, _ = score_response_impact(ResponseActionCategory.ROTATE_CREDENTIALS, context)
    # Non-disruptive action on a HIGH-criticality dependent device is bumped
    # to MEDIUM as a caution margin (see rules.py), never CRITICAL/HIGH.
    assert impact in (ImpactLevel.LOW, ImpactLevel.MEDIUM)


def test_rotate_credentials_on_non_dependent_low_criticality_device_is_low_impact():
    context = _context(DeviceCriticality.LOW, patient_dependency=False)
    impact, _ = score_response_impact(ResponseActionCategory.ROTATE_CREDENTIALS, context)
    assert impact == ImpactLevel.LOW


@pytest.mark.parametrize("action_category", list(ResponseActionCategory))
def test_every_action_category_is_scorable_without_error(action_category):
    context = _context(DeviceCriticality.MEDIUM, patient_dependency=False)
    impact, explanation = score_response_impact(action_category, context)
    assert isinstance(impact, ImpactLevel)
    assert action_category.value in explanation
