import pytest

from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    ResponseActionCategory,
)
from app.schemas.risk import RiskScore


def _threat(incident_id: str = "incident-1") -> ThreatAssessment:
    return ThreatAssessment(
        incident_id=incident_id,
        attack_type=AttackCategory.SPOOFING,
        severity=ImpactLevel.HIGH,
        confidence=0.8,
        propagation_risk=ImpactLevel.MEDIUM,
        reasoning_summary="test",
    )


def _context(
    incident_id: str = "incident-1",
    criticality: DeviceCriticality = DeviceCriticality.HIGH,
    patient_dependency: bool = True,
) -> ClinicalContext:
    return ClinicalContext(
        incident_id=incident_id,
        device_criticality=criticality,
        patient_dependency=patient_dependency,
        clinical_impact_level=ImpactLevel.CRITICAL,
        safety_constraints=[],
    )


def test_calculate_risk_returns_valid_risk_score():
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="shut it down")]

    result = model.calculate_risk(_threat(), _context(), actions)

    assert isinstance(result, RiskScore)
    assert result.incident_id == "incident-1"
    assert 0.0 <= result.cyber_risk <= 1.0
    assert 0.0 <= result.clinical_risk <= 1.0


def test_calculate_risk_has_one_response_impact_entry_per_candidate_action():
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a"),
        CandidateAction(action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="b"),
        CandidateAction(action_category=ResponseActionCategory.ROTATE_CREDENTIALS, description="c"),
    ]

    result = model.calculate_risk(_threat(), _context(), actions)

    assert set(result.response_impact.keys()) == {
        "shutdown",
        "isolate_non_critical",
        "rotate_credentials",
    }


def test_calculate_risk_explanation_is_non_empty_and_names_each_action():
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a"),
        CandidateAction(action_category=ResponseActionCategory.ROTATE_CREDENTIALS, description="b"),
    ]

    result = model.calculate_risk(_threat(), _context(), actions)

    assert len(result.explanation) > 0
    assert "shutdown" in result.explanation
    assert "rotate_credentials" in result.explanation


def test_calculate_risk_raises_on_empty_candidate_responses():
    model = RuleBasedRiskModel()
    with pytest.raises(ValueError, match="non-empty"):
        model.calculate_risk(_threat(), _context(), [])


def test_calculate_risk_raises_on_mismatched_incident_ids():
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a")]
    with pytest.raises(ValueError, match="must match"):
        model.calculate_risk(
            _threat(incident_id="incident-1"), _context(incident_id="incident-2"), actions
        )


def test_calculate_risk_conforms_to_risk_model_protocol():
    from app.risk_engine.model import RiskModel

    model: RiskModel = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a")]
    result = model.calculate_risk(_threat(), _context(), actions)
    assert isinstance(result, RiskScore)
