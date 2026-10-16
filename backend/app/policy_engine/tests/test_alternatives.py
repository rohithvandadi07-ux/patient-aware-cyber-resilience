"""`PolicyDecision.alternatives`: the non-chosen candidates, routed and ranked."""

from app.policy_engine.engine import PolicyEngine
from app.schemas.agents import CandidateAction, ClinicalContext, ProposedResponse
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory
from app.schemas.risk import RiskScore

A = ResponseActionCategory


def _inputs(impacts: dict[A, ImpactLevel], benefits: dict[str, float], chosen: A, patient=False):
    risk = RiskScore(
        incident_id="i-1",
        cyber_risk=0.7,
        clinical_risk=0.4,
        response_impact={a.value: v for a, v in impacts.items()},
        explanation="t",
    )
    proposal = ProposedResponse(
        incident_id="i-1",
        candidate_actions=[CandidateAction(action_category=a, description=a.value) for a in impacts],
        security_benefit=benefits,
        clinical_impact={a.value: v for a, v in impacts.items()},
        recommended_action=chosen,
        rationale="t",
    )
    context = ClinicalContext(
        incident_id="i-1",
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=patient,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )
    return risk, proposal, context


def test_alternatives_exclude_the_chosen_action_and_are_ranked():
    impacts = {
        A.SHUTDOWN: ImpactLevel.CRITICAL,
        A.ISOLATE_NON_CRITICAL: ImpactLevel.MEDIUM,
        A.BLOCK_TRAFFIC: ImpactLevel.LOW,
        A.RESTART_SERVICE: ImpactLevel.LOW,
    }
    benefits = {"block_traffic": 0.5, "restart_service": 0.8, "isolate_non_critical": 0.9, "shutdown": 1.0}
    risk, proposal, context = _inputs(impacts, benefits, chosen=A.SHUTDOWN)
    decision = PolicyEngine().evaluate(risk, proposal, context)

    assert decision.chosen_action is A.SHUTDOWN and decision.requires_human_approval is True
    assert [a.action for a in decision.alternatives] == [
        A.RESTART_SERVICE,  # autonomous, low impact, higher benefit (0.8) than block_traffic (0.5)
        A.BLOCK_TRAFFIC,  # autonomous, low impact
        A.ISOLATE_NON_CRITICAL,  # autonomous (medium, non-dependent) but higher impact
    ]
    assert all(a.requires_human_approval is False for a in decision.alternatives)
    assert decision.alternatives[0].security_benefit == 0.8


def test_alternatives_use_the_same_routing_including_patient_dependency_and_the_confidence_gate():
    impacts = {
        A.SHUTDOWN: ImpactLevel.HIGH,
        A.ISOLATE_CRITICAL: ImpactLevel.HIGH,
        A.BLOCK_TRAFFIC: ImpactLevel.LOW,
    }
    risk, proposal, context = _inputs(impacts, {}, chosen=A.SHUTDOWN, patient=True)
    decision = PolicyEngine(min_autonomous_confidence=0.9).evaluate(risk, proposal, context, 0.7)
    by_action = {a.action: a for a in decision.alternatives}
    assert by_action[A.ISOLATE_CRITICAL].policy_rule_id == "patient_dependent_severe_action"
    assert by_action[A.BLOCK_TRAFFIC].policy_rule_id == "approval_low_detector_confidence"
    assert by_action[A.BLOCK_TRAFFIC].requires_human_approval is True
    assert by_action[A.ISOLATE_CRITICAL].security_benefit is None  # none stated -> None, not 0


def test_unscored_candidates_are_skipped_and_single_action_evaluation_has_none():
    risk, proposal, context = _inputs({A.BLOCK_TRAFFIC: ImpactLevel.LOW}, {}, chosen=A.BLOCK_TRAFFIC)
    proposal.candidate_actions.append(CandidateAction(action_category=A.QUARANTINE_SEGMENT, description="x"))
    decision = PolicyEngine().evaluate(risk, proposal, context)
    assert decision.alternatives == []  # QUARANTINE_SEGMENT was never scored -> skipped, not guessed
    assert PolicyEngine().evaluate_action(risk, context, A.BLOCK_TRAFFIC).alternatives == []
