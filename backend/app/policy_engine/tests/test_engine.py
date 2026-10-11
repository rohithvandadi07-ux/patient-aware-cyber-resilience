import pytest

from app.policy_engine.engine import PolicyEngine
from app.policy_engine.rules import (
    RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL,
    RULE_AUTONOMOUS_LOW_IMPACT,
    RULE_PATIENT_DEPENDENT_SEVERE_ACTION,
)
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import (
    CandidateAction,
    ClinicalContext,
    ProposedResponse,
    ThreatAssessment,
)
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    ResponseActionCategory,
)
from app.schemas.risk import RiskScore


def _context(
    incident_id: str = "incident-1",
    criticality: DeviceCriticality = DeviceCriticality.LOW,
    patient_dependency: bool = False,
) -> ClinicalContext:
    return ClinicalContext(
        incident_id=incident_id,
        device_criticality=criticality,
        patient_dependency=patient_dependency,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )


def _risk_score(
    incident_id: str = "incident-1", response_impact: dict | None = None
) -> RiskScore:
    return RiskScore(
        incident_id=incident_id,
        cyber_risk=0.5,
        clinical_risk=0.5,
        response_impact=response_impact or {"isolate_non_critical": ImpactLevel.LOW},
        explanation="test",
    )


# --- evaluate_action -------------------------------------------------------


def test_evaluate_action_returns_a_policy_decision_naming_the_rule_that_fired():
    engine = PolicyEngine()
    decision = engine.evaluate_action(
        _risk_score(), _context(), ResponseActionCategory.ISOLATE_NON_CRITICAL
    )
    assert decision.incident_id == "incident-1"
    assert decision.chosen_action == ResponseActionCategory.ISOLATE_NON_CRITICAL
    assert decision.requires_human_approval is False
    assert decision.policy_rule_id == RULE_AUTONOMOUS_LOW_IMPACT


def test_evaluate_action_rejects_mismatched_incident_ids_between_risk_score_and_context():
    engine = PolicyEngine()
    with pytest.raises(ValueError, match="incident"):
        engine.evaluate_action(
            _risk_score(incident_id="incident-1"),
            _context(incident_id="incident-2"),
            ResponseActionCategory.ISOLATE_NON_CRITICAL,
        )


def test_evaluate_action_propagates_the_unscored_action_error():
    engine = PolicyEngine()
    with pytest.raises(ValueError, match="response_impact entry"):
        engine.evaluate_action(
            _risk_score(response_impact={}), _context(), ResponseActionCategory.SHUTDOWN
        )


# --- evaluate ---------------------------------------------------------------


def _proposed_response(
    incident_id: str = "incident-1",
    recommended_action: ResponseActionCategory = ResponseActionCategory.ISOLATE_NON_CRITICAL,
) -> ProposedResponse:
    return ProposedResponse(
        incident_id=incident_id,
        candidate_actions=[CandidateAction(action_category=recommended_action, description="test")],
        security_benefit={recommended_action.value: 0.8},
        clinical_impact={recommended_action.value: ImpactLevel.LOW},
        recommended_action=recommended_action,
        rationale="test",
    )


def test_evaluate_routes_on_the_proposed_responses_recommended_action():
    engine = PolicyEngine()
    decision = engine.evaluate(_risk_score(), _proposed_response(), _context())
    assert decision.chosen_action == ResponseActionCategory.ISOLATE_NON_CRITICAL
    assert decision.policy_rule_id == RULE_AUTONOMOUS_LOW_IMPACT


def test_evaluate_rejects_mismatched_incident_ids_between_proposed_response_and_risk_score():
    engine = PolicyEngine()
    with pytest.raises(ValueError, match="incident"):
        engine.evaluate(
            _risk_score(incident_id="incident-1"),
            _proposed_response(incident_id="incident-2"),
            _context(incident_id="incident-1"),
        )


# --- Section 17 Scenario A/B, exercised at the Policy Engine level ---------
#
# Same scope note as risk_engine/tests/test_scenarios.py: the Response
# Orchestrator and blockchain layers don't exist yet, so these assert what
# the Policy Engine itself owns. Unlike test_evaluate_action above, these
# feed PolicyEngine a `RiskScore` genuinely computed by `RuleBasedRiskModel`
# (not a hand-picked response_impact) -- so the assertion is about the real
# composed L5->L6 behavior, not about a response_impact value chosen to make
# the test pass.


def test_scenario_a_auto_approves_isolation_of_a_non_critical_non_dependent_device():
    # "Policy Engine auto-approves network isolation" -- no human-approval
    # step required.
    policy_engine = PolicyEngine()
    risk_model = RuleBasedRiskModel()
    context = _context(
        incident_id="scenario-a", criticality=DeviceCriticality.LOW, patient_dependency=False
    )
    threat = ThreatAssessment(
        incident_id="scenario-a",
        attack_type=AttackCategory.DOS,
        severity=ImpactLevel.HIGH,
        confidence=0.9,
        propagation_risk=ImpactLevel.LOW,
        reasoning_summary="DoS flood pattern against infusion-pump-01's network interface.",
    )
    risk_score = risk_model.calculate_risk(
        threat,
        context,
        [CandidateAction(action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="a")],
    )

    decision = policy_engine.evaluate_action(
        risk_score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL
    )

    assert decision.requires_human_approval is False
    assert decision.policy_rule_id == RULE_AUTONOMOUS_LOW_IMPACT


def test_scenario_b_forces_human_approval_for_shutdown_on_a_patient_dependent_critical_device():
    # "Policy Engine forces requires_human_approval=true even though the
    # Threat Reasoning Agent rates cyber severity as critical" -- the system
    # never autonomously shuts down a patient-dependent, high-criticality
    # device, regardless of attack severity. This is the one assertion that
    # most directly tests the central research claim.
    policy_engine = PolicyEngine()
    risk_model = RuleBasedRiskModel()
    context = _context(
        incident_id="scenario-b", criticality=DeviceCriticality.HIGH, patient_dependency=True
    )
    threat = ThreatAssessment(
        incident_id="scenario-b",
        attack_type=AttackCategory.MITM_INJECTION,
        severity=ImpactLevel.CRITICAL,
        confidence=0.95,
        propagation_risk=ImpactLevel.HIGH,
        reasoning_summary="Command-injection pattern targeting ventilator-01's control interface.",
    )
    risk_score = risk_model.calculate_risk(
        threat, context, [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a")]
    )
    assert risk_score.cyber_risk > 0.8  # the threat is genuinely scored as near-maximal

    decision = policy_engine.evaluate_action(risk_score, context, ResponseActionCategory.SHUTDOWN)

    assert decision.requires_human_approval is True
    assert decision.policy_rule_id == RULE_PATIENT_DEPENDENT_SEVERE_ACTION


def test_scenario_b_still_requires_approval_for_the_gentler_alternative_under_the_gap_fill_rule():
    # Honest finding, not the outcome one might expect from "a safer action
    # is offered": `RuleBasedRiskModel` scores isolate_non_critical as
    # response_impact=HIGH on this HIGH-criticality, patient-dependent device
    # (see risk_engine/rules.py's moderate-disruption tier), which is >=
    # HIGH and therefore requires approval on its own -- this device's
    # patient-dependency floor means almost nothing routes autonomously for
    # it under the current conservative rule table, not just SHUTDOWN. The
    # "safer alternative" Section 17 describes is safer in the sense of a
    # lower response_impact rank and a real alternative for a human approver
    # to choose, not in the sense of being auto-approved.
    policy_engine = PolicyEngine()
    risk_model = RuleBasedRiskModel()
    context = _context(
        incident_id="scenario-b", criticality=DeviceCriticality.HIGH, patient_dependency=True
    )
    threat = ThreatAssessment(
        incident_id="scenario-b",
        attack_type=AttackCategory.MITM_INJECTION,
        severity=ImpactLevel.CRITICAL,
        confidence=0.95,
        propagation_risk=ImpactLevel.HIGH,
        reasoning_summary="Command-injection pattern targeting ventilator-01's control interface.",
    )
    risk_score = risk_model.calculate_risk(
        threat,
        context,
        [CandidateAction(action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="a")],
    )

    decision = policy_engine.evaluate_action(
        risk_score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL
    )

    assert decision.requires_human_approval is True


def test_scenario_b_variant_with_lower_criticality_hits_the_medium_patient_dependent_gap_fill():
    # Demonstrates the one case in Scenario B's family that *does* exercise
    # the gap-fill rule rather than the unconditional-approval or
    # high-impact rules: a patient-dependent device below HIGH criticality,
    # where a moderate-disruption action scores response_impact=MEDIUM.
    policy_engine = PolicyEngine()
    risk_model = RuleBasedRiskModel()
    context = _context(
        incident_id="scenario-b-variant",
        criticality=DeviceCriticality.MEDIUM,
        patient_dependency=True,
    )
    threat = ThreatAssessment(
        incident_id="scenario-b-variant",
        attack_type=AttackCategory.MITM_INJECTION,
        severity=ImpactLevel.CRITICAL,
        confidence=0.95,
        propagation_risk=ImpactLevel.HIGH,
        reasoning_summary="Command-injection pattern targeting a medium-criticality monitor.",
    )
    risk_score = risk_model.calculate_risk(
        threat,
        context,
        [
            CandidateAction(
                action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="a"
            )
        ],
    )

    decision = policy_engine.evaluate_action(
        risk_score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL
    )

    assert decision.requires_human_approval is True
    assert decision.policy_rule_id == RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL
