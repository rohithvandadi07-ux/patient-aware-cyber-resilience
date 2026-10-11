import pytest

from app.policy_engine.rules import (
    RULE_APPROVAL_HIGH_IMPACT,
    RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL,
    RULE_AUTONOMOUS_LOW_IMPACT,
    RULE_AUTONOMOUS_MEDIUM_NON_DEPENDENT,
    RULE_PATIENT_DEPENDENT_SEVERE_ACTION,
    classify_routing,
    decide_routing,
    get_response_impact_for_action,
)
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory
from app.schemas.risk import RiskScore

# --- classify_routing -----------------------------------------------------

# A non-unconditional-approval action, used throughout to probe the
# response_impact-driven rules without the rule-3 short-circuit firing.
_ORDINARY_ACTION = ResponseActionCategory.ISOLATE_NON_CRITICAL


@pytest.mark.parametrize(
    "action_category", [ResponseActionCategory.SHUTDOWN, ResponseActionCategory.ISOLATE_CRITICAL]
)
@pytest.mark.parametrize("response_impact", list(ImpactLevel))
def test_patient_dependent_severe_action_requires_approval_regardless_of_response_impact(
    action_category, response_impact
):
    # Rule 3's unconditional-approval set must fire even when response_impact
    # is LOW -- it is checked independently of (and before) the
    # response_impact ladder, per the module's own defense-in-depth rationale.
    requires_approval, rule_id, rationale = classify_routing(
        response_impact, patient_dependency=True, action_category=action_category
    )
    assert requires_approval is True
    assert rule_id == RULE_PATIENT_DEPENDENT_SEVERE_ACTION
    assert action_category.value in rationale


@pytest.mark.parametrize(
    "action_category", [ResponseActionCategory.SHUTDOWN, ResponseActionCategory.ISOLATE_CRITICAL]
)
def test_unconditional_approval_actions_do_not_force_approval_when_not_patient_dependent(
    action_category,
):
    # Rule 3 names "patient_dependency=true AND action in {...}" -- without
    # patient dependency, these actions fall through to the ordinary
    # response_impact ladder like any other action.
    requires_approval, rule_id, _ = classify_routing(
        ImpactLevel.LOW, patient_dependency=False, action_category=action_category
    )
    assert requires_approval is False
    assert rule_id == RULE_AUTONOMOUS_LOW_IMPACT


@pytest.mark.parametrize("patient_dependency", [True, False])
def test_low_impact_is_autonomous_regardless_of_patient_dependency(patient_dependency):
    requires_approval, rule_id, rationale = classify_routing(
        ImpactLevel.LOW, patient_dependency=patient_dependency, action_category=_ORDINARY_ACTION
    )
    assert requires_approval is False
    assert rule_id == RULE_AUTONOMOUS_LOW_IMPACT
    assert "low" in rationale


def test_medium_impact_non_dependent_is_autonomous():
    requires_approval, rule_id, rationale = classify_routing(
        ImpactLevel.MEDIUM, patient_dependency=False, action_category=_ORDINARY_ACTION
    )
    assert requires_approval is False
    assert rule_id == RULE_AUTONOMOUS_MEDIUM_NON_DEPENDENT
    assert "medium" in rationale


def test_medium_impact_patient_dependent_is_the_conservative_gap_fill():
    requires_approval, rule_id, rationale = classify_routing(
        ImpactLevel.MEDIUM, patient_dependency=True, action_category=_ORDINARY_ACTION
    )
    assert requires_approval is True
    assert rule_id == RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL
    assert "gap-fill" in rationale


@pytest.mark.parametrize("response_impact", [ImpactLevel.HIGH, ImpactLevel.CRITICAL])
@pytest.mark.parametrize("patient_dependency", [True, False])
def test_high_or_critical_impact_requires_approval_regardless_of_patient_dependency(
    response_impact, patient_dependency
):
    requires_approval, rule_id, rationale = classify_routing(
        response_impact, patient_dependency=patient_dependency, action_category=_ORDINARY_ACTION
    )
    assert requires_approval is True
    assert rule_id == RULE_APPROVAL_HIGH_IMPACT
    assert response_impact.value in rationale


def test_rule_precedence_is_first_match_wins_patient_dependent_severe_before_low_impact():
    # Direct regression for the precedence this module documents: a LOW
    # response_impact must not short-circuit rule 3 for SHUTDOWN on a
    # patient-dependent device.
    requires_approval, rule_id, _ = classify_routing(
        ImpactLevel.LOW, patient_dependency=True, action_category=ResponseActionCategory.SHUTDOWN
    )
    assert requires_approval is True
    assert rule_id == RULE_PATIENT_DEPENDENT_SEVERE_ACTION


# --- get_response_impact_for_action --------------------------------------


def test_get_response_impact_for_action_returns_the_scored_value():
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.5,
        clinical_risk=0.5,
        response_impact={"isolate_non_critical": ImpactLevel.MEDIUM},
        explanation="test",
    )
    impact = get_response_impact_for_action(risk_score, ResponseActionCategory.ISOLATE_NON_CRITICAL)
    assert impact == ImpactLevel.MEDIUM


def test_get_response_impact_for_action_raises_clear_error_when_action_was_never_scored():
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.5,
        clinical_risk=0.5,
        response_impact={"isolate_non_critical": ImpactLevel.MEDIUM},
        explanation="test",
    )
    with pytest.raises(ValueError, match="incident-1"):
        get_response_impact_for_action(risk_score, ResponseActionCategory.SHUTDOWN)


# --- decide_routing --------------------------------------------------------


def _context(patient_dependency: bool) -> ClinicalContext:
    return ClinicalContext(
        incident_id="incident-1",
        device_criticality=DeviceCriticality.MEDIUM,
        patient_dependency=patient_dependency,
        clinical_impact_level=ImpactLevel.MEDIUM,
        safety_constraints=[],
    )


def test_decide_routing_looks_up_response_impact_and_classifies_it():
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.9,
        clinical_risk=0.9,
        response_impact={"shutdown": ImpactLevel.CRITICAL},
        explanation="test",
    )
    requires_approval, rule_id, _ = decide_routing(
        risk_score, _context(patient_dependency=True), ResponseActionCategory.SHUTDOWN
    )
    assert requires_approval is True
    assert rule_id == RULE_PATIENT_DEPENDENT_SEVERE_ACTION


def test_decide_routing_matches_classify_routing_for_an_autonomous_case():
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.1,
        clinical_risk=0.1,
        response_impact={"isolate_non_critical": ImpactLevel.LOW},
        explanation="test",
    )
    result = decide_routing(
        risk_score, _context(patient_dependency=False), ResponseActionCategory.ISOLATE_NON_CRITICAL
    )
    expected = classify_routing(ImpactLevel.LOW, False, ResponseActionCategory.ISOLATE_NON_CRITICAL)
    assert result == expected


def test_decide_routing_propagates_the_unscored_action_error():
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.1,
        clinical_risk=0.1,
        response_impact={},
        explanation="test",
    )
    with pytest.raises(ValueError, match="response_impact entry"):
        decide_routing(risk_score, _context(patient_dependency=False), ResponseActionCategory.SHUTDOWN)
