from types import SimpleNamespace

from app.agents.grounding import ground_clinical_context
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel
from app.schemas.patient import AcuityBand, Consciousness, PatientState, Vitals


def _device(criticality=DeviceCriticality.MEDIUM, dependent=True):
    return SimpleNamespace(criticality=criticality, patient_dependency=dependent)


def _patient(band, news2):
    return PatientState(
        patient_id="p-1",
        device_ids=["d-1"],
        profile="test",
        simulated_minute=0,
        vitals=Vitals(
            respiration_rate=18,
            spo2=95,
            on_supplemental_oxygen=False,
            systolic_bp=120,
            pulse=80,
            consciousness=Consciousness.ALERT,
            temperature_c=37.0,
        ),
        news2_score=news2,
        score_breakdown={},
        single_parameter_red_flag=False,
        acuity_band=band,
    )


def _ctx(**kw):
    base = dict(
        incident_id="inc-1",
        device_criticality=DeviceCriticality.MEDIUM,
        patient_dependency=True,
        clinical_impact_level=ImpactLevel.MEDIUM,
    )
    return ClinicalContext(**{**base, **kw})


def test_acuity_is_filled_from_registry():
    out, corrections = ground_clinical_context(_ctx(), _device(), _patient(AcuityBand.MEDIUM, 5))
    assert out.patient_acuity == AcuityBand.MEDIUM and out.news2_score == 5
    assert corrections == []  # enrichment, not a correction of the agent


def test_high_acuity_raises_clinical_impact_floor():
    ctx = _ctx(clinical_impact_level=ImpactLevel.LOW)
    out, corrections = ground_clinical_context(ctx, _device(), _patient(AcuityBand.HIGH, 8))
    assert out.clinical_impact_level == ImpactLevel.HIGH
    assert any("acuity is HIGH" in c for c in corrections)


def test_llm_invented_acuity_is_overwritten():
    ctx = _ctx(patient_acuity=AcuityBand.LOW, news2_score=0)
    out, _ = ground_clinical_context(ctx, _device(), _patient(AcuityBand.HIGH, 9))
    assert out.patient_acuity == AcuityBand.HIGH and out.news2_score == 9


def test_acuity_without_linked_patient_is_cleared():
    ctx = _ctx(patient_acuity=AcuityBand.HIGH, news2_score=9)
    out, corrections = ground_clinical_context(ctx, _device(), None)
    assert out.patient_acuity is None and out.news2_score is None
    assert corrections


def test_no_patient_no_change():
    ctx = _ctx()
    out, corrections = ground_clinical_context(ctx, _device(), None)
    assert out == ctx and corrections == []
