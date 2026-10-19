from app.policy_engine.rules import (
    RULE_APPROVAL_HIGH_ACUITY_PATIENT,
    RULE_AUTONOMOUS_LOW_IMPACT,
    RULE_PATIENT_DEPENDENT_SEVERE_ACTION,
    classify_routing,
)
from app.schemas.enums import ImpactLevel, ResponseActionCategory
from app.schemas.patient import AcuityBand

RESTRICT = ResponseActionCategory.RESTRICT_COMMUNICATION


def test_high_acuity_disruptive_action_needs_approval_even_at_low_impact():
    approval, rule, why = classify_routing(ImpactLevel.LOW, True, RESTRICT, AcuityBand.HIGH)
    assert approval is True
    assert rule == RULE_APPROVAL_HIGH_ACUITY_PATIENT
    assert "HIGH acuity" in why


def test_same_case_without_acuity_is_still_autonomous():
    approval, rule, _ = classify_routing(ImpactLevel.LOW, True, RESTRICT)
    assert approval is False and rule == RULE_AUTONOMOUS_LOW_IMPACT


def test_medium_acuity_does_not_trigger_the_rule():
    approval, rule, _ = classify_routing(ImpactLevel.LOW, True, RESTRICT, AcuityBand.MEDIUM)
    assert approval is False and rule == RULE_AUTONOMOUS_LOW_IMPACT


def test_non_disruptive_action_stays_autonomous_for_high_acuity_patient():
    approval, rule, _ = classify_routing(
        ImpactLevel.LOW, True, ResponseActionCategory.ROTATE_CREDENTIALS, AcuityBand.HIGH
    )
    assert approval is False and rule == RULE_AUTONOMOUS_LOW_IMPACT


def test_rule_requires_patient_dependency():
    approval, rule, _ = classify_routing(ImpactLevel.LOW, False, RESTRICT, AcuityBand.HIGH)
    assert approval is False and rule == RULE_AUTONOMOUS_LOW_IMPACT


def test_section_13_unconditional_rule_keeps_precedence():
    _, rule, _ = classify_routing(
        ImpactLevel.LOW, True, ResponseActionCategory.SHUTDOWN, AcuityBand.HIGH
    )
    assert rule == RULE_PATIENT_DEPENDENT_SEVERE_ACTION
