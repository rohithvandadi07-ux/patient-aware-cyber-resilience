from app.risk_engine.rules import score_clinical_risk, score_response_impact
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory
from app.schemas.patient import AcuityBand


def _ctx(**kw):
    base = dict(
        incident_id="inc-1",
        device_criticality=DeviceCriticality.MEDIUM,
        patient_dependency=True,
        clinical_impact_level=ImpactLevel.MEDIUM,
    )
    return ClinicalContext(**{**base, **kw})


def test_no_patient_is_unchanged():
    score, _ = score_clinical_risk(_ctx())
    assert score == 0.55  # patient-dependency floor, no acuity bump


def test_clinical_risk_bumps_by_acuity():
    base, _ = score_clinical_risk(_ctx())
    low, _ = score_clinical_risk(_ctx(patient_acuity=AcuityBand.LOW, news2_score=1))
    med, _ = score_clinical_risk(_ctx(patient_acuity=AcuityBand.MEDIUM, news2_score=5))
    high, expl = score_clinical_risk(_ctx(patient_acuity=AcuityBand.HIGH, news2_score=8))
    assert low == base
    assert med == round(base + 0.05, 4)
    assert high == round(base + 0.10, 4)
    assert "acuity high" in expl and "NEWS2 8" in expl


def test_severe_action_becomes_critical_for_high_acuity_patient():
    action = ResponseActionCategory.ISOLATE_CRITICAL
    base, _ = score_response_impact(action, _ctx())
    assert base == ImpactLevel.HIGH
    level, expl = score_response_impact(action, _ctx(patient_acuity=AcuityBand.HIGH, news2_score=8))
    assert level == ImpactLevel.CRITICAL
    assert "acuity is HIGH" in expl


def test_medium_acuity_does_not_escalate_response_impact():
    action = ResponseActionCategory.ISOLATE_CRITICAL
    level, _ = score_response_impact(action, _ctx(patient_acuity=AcuityBand.MEDIUM, news2_score=5))
    assert level == ImpactLevel.HIGH


def test_moderate_action_rises_one_tier_for_high_acuity_patient():
    action = ResponseActionCategory.RESTRICT_COMMUNICATION
    base, _ = score_response_impact(action, _ctx())
    level, _ = score_response_impact(action, _ctx(patient_acuity=AcuityBand.HIGH, news2_score=8))
    assert base == ImpactLevel.MEDIUM
    assert level == ImpactLevel.HIGH


def test_non_disruptive_action_is_not_escalated():
    action = ResponseActionCategory.ROTATE_CREDENTIALS
    base, _ = score_response_impact(action, _ctx())
    level, _ = score_response_impact(action, _ctx(patient_acuity=AcuityBand.HIGH, news2_score=8))
    assert level == base == ImpactLevel.LOW


def test_no_escalation_without_patient_dependency():
    action = ResponseActionCategory.ISOLATE_CRITICAL
    ctx = _ctx(patient_dependency=False, patient_acuity=AcuityBand.HIGH, news2_score=8)
    base, _ = score_response_impact(action, _ctx(patient_dependency=False))
    level, _ = score_response_impact(action, ctx)
    assert level == base
