"""The Policy Engine's opt-in confidence gate (`rules.apply_confidence_gate`)."""

import pytest

from app.evaluation.baseline_systems import (
    CONFIDENCE_GATE_RULE_ID,
    decide_full_system,
    decide_full_system_confidence_gated,
    detection_outcome_from_row,
    sample_device_contexts,
)
from app.policy_engine.engine import PolicyEngine
from app.policy_engine.rules import (
    RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE,
    RULE_APPROVAL_UNKNOWN_DETECTOR_CONFIDENCE,
    RULE_AUTONOMOUS_LOW_IMPACT,
    RULE_PATIENT_DEPENDENT_SEVERE_ACTION,
    apply_confidence_gate,
)
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory
from app.schemas.risk import RiskScore

AUTONOMOUS = (False, RULE_AUTONOMOUS_LOW_IMPACT, "ok")
APPROVAL = (True, RULE_PATIENT_DEPENDENT_SEVERE_ACTION, "needs a human")


def test_gate_rule_id_matches_the_experiment_only_gate():
    assert RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE == CONFIDENCE_GATE_RULE_ID


def test_disabled_gate_changes_nothing_whatever_the_confidence():
    for confidence in (None, 0.0, 0.5, 1.0):
        assert apply_confidence_gate(AUTONOMOUS, confidence, None) == AUTONOMOUS
        assert apply_confidence_gate(APPROVAL, confidence, None) == APPROVAL


def test_low_confidence_autonomous_decision_goes_to_a_human():
    requires, rule, rationale = apply_confidence_gate(AUTONOMOUS, 0.7, 0.9)
    assert requires is True and rule == RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE
    assert RULE_AUTONOMOUS_LOW_IMPACT in rationale  # says what it would otherwise have been


def test_confidence_at_or_above_the_minimum_keeps_autonomy():
    assert apply_confidence_gate(AUTONOMOUS, 0.9, 0.9) == AUTONOMOUS
    assert apply_confidence_gate(AUTONOMOUS, 1.0, 0.9) == AUTONOMOUS


def test_unknown_confidence_fails_closed_when_the_gate_is_on():
    requires, rule, _ = apply_confidence_gate(AUTONOMOUS, None, 0.9)
    assert requires is True and rule == RULE_APPROVAL_UNKNOWN_DETECTOR_CONFIDENCE


def test_gate_never_loosens_a_decision_that_already_needs_approval():
    for confidence in (None, 0.0, 1.0):
        assert apply_confidence_gate(APPROVAL, confidence, 0.9) == APPROVAL


@pytest.mark.parametrize("bad", [0.0, -0.1, 1.5])
def test_engine_rejects_an_out_of_range_minimum(bad):
    with pytest.raises(ValueError, match="min_autonomous_confidence"):
        PolicyEngine(min_autonomous_confidence=bad)


def _score_and_context(impact: ImpactLevel):
    score = RiskScore(
        incident_id="i-1",
        cyber_risk=0.5,
        clinical_risk=0.5,
        response_impact={"isolate_non_critical": impact},
        explanation="t",
    )
    context = ClinicalContext(
        incident_id="i-1",
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )
    return score, context


def test_engine_default_is_unchanged_and_ignores_confidence():
    score, context = _score_and_context(ImpactLevel.LOW)
    decision = PolicyEngine().evaluate_action(
        score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL, detection_confidence=0.01
    )
    assert decision.requires_human_approval is False
    assert decision.policy_rule_id == RULE_AUTONOMOUS_LOW_IMPACT


def test_engine_with_gate_demotes_low_confidence_and_keeps_confident():
    score, context = _score_and_context(ImpactLevel.LOW)
    engine = PolicyEngine(min_autonomous_confidence=0.9)
    low = engine.evaluate_action(score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL, 0.7)
    high = engine.evaluate_action(score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL, 0.95)
    unknown = engine.evaluate_action(score, context, ResponseActionCategory.ISOLATE_NON_CRITICAL)
    assert (low.requires_human_approval, low.policy_rule_id) == (True, RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE)
    assert high.requires_human_approval is False
    assert unknown.policy_rule_id == RULE_APPROVAL_UNKNOWN_DETECTOR_CONFIDENCE


def test_real_engine_gate_agrees_with_the_experiment_only_gate_on_random_trials():
    """The evaluation reports were produced with the experiment-only gate in
    baseline_systems.py; the shipped Policy Engine gate must route identically."""
    tau = 0.9
    risk_model, plain = RuleBasedRiskModel(), PolicyEngine()
    gated_engine = PolicyEngine(min_autonomous_confidence=tau)
    contexts = sample_device_contexts(400, seed=5)
    confidences = [0.6 + 0.4 * ((i * 37) % 100) / 100 for i in range(400)]
    for i, (context, conf) in enumerate(zip(contexts, confidences, strict=True)):
        detection = detection_outcome_from_row("dos", "dos", conf)
        experiment = decide_full_system_confidence_gated(
            detection,
            context,
            f"i-{i}",
            risk_model=risk_model,
            policy_engine=plain,
            min_autonomous_confidence=tau,
        )
        # Same inputs through the shipped engine: base decision from the plain engine's
        # inputs, but routed by the gated engine with the detector confidence supplied.
        shipped = decide_full_system(
            detection,
            context,
            f"i-{i}",
            risk_model=risk_model,
            policy_engine=_ConfidenceBound(gated_engine, conf),
        )
        assert shipped.executed_action == experiment.executed_action, i
        assert shipped.requires_human_approval == experiment.requires_human_approval, i


class _ConfidenceBound:
    """Adapter: lets the evaluation harness (which calls `evaluate_action` with no
    confidence) drive an engine with the confidence of the current trial."""

    def __init__(self, engine: PolicyEngine, confidence: float) -> None:
        self._engine, self._confidence = engine, confidence

    def evaluate_action(self, risk_score, context, action):
        return self._engine.evaluate_action(risk_score, context, action, self._confidence)
