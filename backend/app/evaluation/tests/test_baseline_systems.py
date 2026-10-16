import pytest

from app.evaluation.baseline_systems import (
    CONFIDENCE_GATE_RULE_ID,
    AblationName,
    DetectionOutcome,
    DeviceContext,
    SystemName,
    decide_detection_only,
    decide_detection_plus_agentic_ai,
    decide_detection_plus_risk_engine,
    decide_fixed_response,
    decide_full_system,
    decide_full_system_confidence_gated,
    decide_full_system_variant,
    detection_outcome_from_row,
    is_high_stakes,
    is_unnecessary_isolation,
    is_unsafe_autonomous_action,
    propose_action,
    recovery_result_would_require_reinvestigation,
    sample_device_contexts,
)
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory


def _attack(confidence: float, label: str = "dos") -> DetectionOutcome:
    return detection_outcome_from_row(ground_truth_label=label, predicted_label=label, confidence=confidence)


def _false_positive(confidence: float, predicted_label: str = "dos") -> DetectionOutcome:
    return detection_outcome_from_row(
        ground_truth_label="unknown", predicted_label=predicted_label, confidence=confidence
    )


def _true_negative(confidence: float = 0.95) -> DetectionOutcome:
    return detection_outcome_from_row(
        ground_truth_label="unknown", predicted_label="unknown", confidence=confidence
    )


def _missed_attack(confidence: float = 0.3, label: str = "dos") -> DetectionOutcome:
    # Below the confidence threshold -- never fires, same as a benign prediction would.
    return detection_outcome_from_row(ground_truth_label=label, predicted_label=label, confidence=confidence)


class TestSampleDeviceContexts:
    def test_reproducible_with_same_seed(self):
        a = sample_device_contexts(50, seed=7)
        b = sample_device_contexts(50, seed=7)
        assert a == b

    def test_covers_the_full_context_space(self):
        contexts = sample_device_contexts(500, seed=7)
        seen = {(c.device_criticality, c.patient_dependency) for c in contexts}
        # 3 criticalities x 2 dependency values -- 500 samples should hit all 6
        # combinations with overwhelming probability; a flaky failure here
        # would indicate a real sampling bug, not bad luck.
        assert len(seen) == 6


class TestDetectionOutcomeFromRow:
    def test_benign_prediction_never_fires(self):
        outcome = detection_outcome_from_row(
            ground_truth_label="dos", predicted_label="unknown", confidence=0.99
        )
        assert outcome.fired is False

    def test_low_confidence_prediction_never_fires(self):
        outcome = detection_outcome_from_row(ground_truth_label="dos", predicted_label="dos", confidence=0.1)
        assert outcome.fired is False

    def test_high_confidence_non_benign_fires(self):
        outcome = detection_outcome_from_row(ground_truth_label="dos", predicted_label="dos", confidence=0.9)
        assert outcome.fired is True

    def test_ground_truth_is_attack_and_false_positive_flags(self):
        fp = _false_positive(0.9)
        assert fp.fired is True
        assert fp.ground_truth_is_attack is False
        assert fp.is_false_positive is True

        tp = _attack(0.9)
        assert tp.ground_truth_is_attack is True
        assert tp.is_false_positive is False


class TestProposeAction:
    def test_high_confidence_recommends_shutdown(self):
        detection = _attack(0.95)
        assert propose_action(detection) == ResponseActionCategory.SHUTDOWN

    def test_moderate_confidence_recommends_isolate_non_critical(self):
        detection = _attack(0.7)
        assert propose_action(detection) == ResponseActionCategory.ISOLATE_NON_CRITICAL


class TestDecideDetectionOnly:
    def test_never_executes_even_when_detection_fires(self):
        detection = _attack(0.95)
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_detection_only(detection, context)
        assert decision.system == SystemName.DETECTION_ONLY
        assert decision.executed_action is None
        assert decision.proposed_action is None


class TestDecideFixedResponse:
    def test_no_action_when_detection_does_not_fire(self):
        detection = _missed_attack()
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_fixed_response(detection, context)
        assert decision.executed_action is None

    def test_executes_unconditionally_even_on_high_stakes_device(self):
        """The whole point of this baseline: it does not look at context at
        all, so it blindly shuts down a patient-dependent, HIGH-criticality
        device just the same as any other -- this is what the full system
        is supposed to improve on."""
        detection = _attack(0.95)
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_fixed_response(detection, context)
        assert decision.executed_action == ResponseActionCategory.SHUTDOWN
        assert decision.requires_human_approval is False
        assert is_high_stakes(context) is True
        assert is_unsafe_autonomous_action(decision) is True


class TestDecideFullSystem:
    @pytest.fixture
    def engines(self):
        return RuleBasedRiskModel(), PolicyEngine()

    def test_requires_approval_for_shutdown_on_high_stakes_device(self, engines):
        """The central research claim (Section 17 Scenario B), exercised
        directly through decide_full_system rather than only through the
        two hand-written scenario tests."""
        risk_model, policy_engine = engines
        detection = _attack(0.95)  # high confidence -> propose_action recommends shutdown
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_full_system(
            detection, context, "EVAL-test-1", risk_model=risk_model, policy_engine=policy_engine
        )
        assert decision.proposed_action == ResponseActionCategory.SHUTDOWN
        assert decision.requires_human_approval is True
        assert decision.executed_action is None
        assert is_unsafe_autonomous_action(decision) is False

    def test_autonomous_execution_allowed_on_low_stakes_device(self, engines):
        risk_model, policy_engine = engines
        detection = _attack(0.7)  # moderate confidence -> isolate_non_critical
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_full_system(
            detection, context, "EVAL-test-2", risk_model=risk_model, policy_engine=policy_engine
        )
        assert decision.proposed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL
        assert decision.requires_human_approval is False
        assert decision.executed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL

    def test_no_detection_means_no_decision_either_way(self, engines):
        risk_model, policy_engine = engines
        detection = _missed_attack()
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_full_system(
            detection, context, "EVAL-test-3", risk_model=risk_model, policy_engine=policy_engine
        )
        assert decision.proposed_action is None
        assert decision.executed_action is None
        assert decision.requires_human_approval is None


class TestUnsafeAndUnnecessaryMetrics:
    def test_full_system_never_unsafe_on_a_sweep_of_high_stakes_confidences(self):
        """A stronger, sweep-based version of the single-point scenario
        test above -- across every confidence level that can fire a
        detection, the full system must never autonomously execute a
        disruptive action on a high-stakes real attack."""
        risk_model, policy_engine = RuleBasedRiskModel(), PolicyEngine()
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        for confidence in (0.6, 0.7, 0.8, 0.85, 0.9, 0.99):
            detection = _attack(confidence)
            decision = decide_full_system(
                detection,
                context,
                f"EVAL-sweep-{confidence}",
                risk_model=risk_model,
                policy_engine=policy_engine,
            )
            assert is_unsafe_autonomous_action(decision) is False, (
                f"confidence={confidence} produced an unsafe autonomous action"
            )

    def test_unnecessary_isolation_detected_for_fixed_response_false_positive(self):
        detection = _false_positive(0.95)
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_fixed_response(detection, context)
        assert is_unnecessary_isolation(decision) is True

    def test_true_negative_is_not_a_false_positive_and_never_flagged(self):
        detection = _true_negative()
        assert detection.fired is False
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_fixed_response(detection, context)
        assert is_unnecessary_isolation(decision) is False


class TestDecideDetectionPlusAgenticAI:
    def test_no_action_when_detection_does_not_fire(self):
        detection = _missed_attack()
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_detection_plus_agentic_ai(detection, context, "EVAL-agentic-1")
        assert decision.system == SystemName.DETECTION_PLUS_AGENTIC_AI
        assert decision.executed_action is None
        assert decision.requires_human_approval is None

    def test_holds_for_approval_on_patient_dependent_high_severity(self):
        """High-confidence attack (severity HIGH/CRITICAL) on a
        patient-dependent device: the heuristic's first disjunct fires."""
        detection = _attack(0.95)
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=True)
        decision = decide_detection_plus_agentic_ai(detection, context, "EVAL-agentic-2")
        assert decision.requires_human_approval is True
        assert decision.executed_action is None

    def test_executes_autonomously_on_low_stakes_low_severity(self):
        detection = _attack(0.7)
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
        decision = decide_detection_plus_agentic_ai(detection, context, "EVAL-agentic-3")
        assert decision.requires_human_approval is False
        assert decision.executed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL

    def test_holds_for_approval_whenever_clinical_impact_itself_is_high(self):
        """HIGH-criticality, non-patient-dependent device -> clinical_impact_level
        MEDIUM, so this exercises the second disjunct (impact HIGH/CRITICAL)
        rather than the patient-dependency one -- patient-dependent devices
        are always at least HIGH impact (clinical_context_for), so this path
        is reached whenever patient_dependency=True regardless of severity."""
        detection = _attack(0.7)  # moderate severity -- would NOT trip the severity disjunct
        context = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=True)
        decision = decide_detection_plus_agentic_ai(detection, context, "EVAL-agentic-4")
        assert decision.requires_human_approval is True


class TestDecideDetectionPlusRiskEngine:
    @pytest.fixture
    def engines(self):
        return RuleBasedRiskModel(), PolicyEngine()

    def test_no_action_when_detection_does_not_fire(self, engines):
        risk_model, policy_engine = engines
        detection = _missed_attack()
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_detection_plus_risk_engine(
            detection, context, "EVAL-riskonly-1", risk_model=risk_model, policy_engine=policy_engine
        )
        assert decision.executed_action is None
        assert decision.requires_human_approval is None

    def test_blind_to_real_high_stakes_context_executes_autonomously(self, engines):
        """The whole point of this system: it feeds the real risk/policy
        engine a fixed stub context, not the trial's real one -- so, unlike
        full_system, it autonomously executes a severe action even though
        the real device context is HIGH-criticality + patient-dependent."""
        risk_model, policy_engine = engines
        detection = _attack(0.95)  # -> propose_action recommends shutdown
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_detection_plus_risk_engine(
            detection, context, "EVAL-riskonly-2", risk_model=risk_model, policy_engine=policy_engine
        )
        assert decision.requires_human_approval is False
        assert decision.executed_action == ResponseActionCategory.SHUTDOWN
        # Metrics are judged against the trial's *real* context, so this is
        # correctly counted as unsafe even though the engine never saw it.
        assert is_unsafe_autonomous_action(decision) is True


class TestDecideFullSystemVariant:
    @pytest.fixture
    def engines(self):
        return RuleBasedRiskModel(), PolicyEngine()

    def test_without_healthcare_context_never_changes_full_system_routing(self, engines):
        """Structural claim made in run_baseline_comparison.py's report:
        flattening clinical_impact_level cannot change a routing decision
        under the current Policy Engine, because classify_routing never
        reads clinical_risk -- checked directly here across a sweep of
        contexts, not just asserted."""
        risk_model, policy_engine = engines
        for criticality in DeviceCriticality:
            for patient_dependency in (True, False):
                context = DeviceContext(device_criticality=criticality, patient_dependency=patient_dependency)
                detection = _attack(0.95)
                full = decide_full_system(
                    detection, context, "EVAL-variant-hc", risk_model=risk_model, policy_engine=policy_engine
                )
                variant = decide_full_system_variant(
                    detection,
                    context,
                    "EVAL-variant-hc",
                    risk_model=risk_model,
                    policy_engine=policy_engine,
                    ablation=AblationName.WITHOUT_HEALTHCARE_CONTEXT,
                    flat_clinical_impact=ImpactLevel.MEDIUM,
                )
                assert variant.executed_action == full.executed_action
                assert variant.requires_human_approval == full.requires_human_approval

    def test_without_response_impact_assessment_can_permit_what_full_system_blocks(self, engines):
        """Forcing response_impact to LOW removes the only rule that would
        otherwise have blocked this case: a MEDIUM-criticality,
        patient-dependent device given the MODERATE action
        (isolate_non_critical, deliberately not shutdown/isolate_critical --
        those are caught unconditionally by rule 3 regardless of
        response_impact, so they would not demonstrate this ablation's
        effect) -- full_system requires approval here only via the
        response_impact=medium + patient_dependency "gap fill" rule; with
        that term forced to LOW, nothing blocks autonomous execution."""
        risk_model, policy_engine = engines
        detection = _attack(0.7)  # moderate confidence -> isolate_non_critical
        context = DeviceContext(device_criticality=DeviceCriticality.MEDIUM, patient_dependency=True)

        full = decide_full_system(
            detection, context, "EVAL-variant-ria", risk_model=risk_model, policy_engine=policy_engine
        )
        assert full.proposed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL
        assert full.requires_human_approval is True

        variant = decide_full_system_variant(
            detection,
            context,
            "EVAL-variant-ria",
            risk_model=risk_model,
            policy_engine=policy_engine,
            ablation=AblationName.WITHOUT_RESPONSE_IMPACT_ASSESSMENT,
            disable_response_impact_assessment=True,
        )
        assert variant.requires_human_approval is False
        assert variant.executed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL


class TestRecoveryResultWouldRequireReinvestigation:
    @pytest.fixture
    def engines(self):
        return RuleBasedRiskModel(), PolicyEngine()

    def test_false_when_nothing_executed(self):
        detection = _missed_attack()
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_detection_only(detection, context)
        assert recovery_result_would_require_reinvestigation(detection, context, decision) is False

    def test_false_on_a_false_positive_even_if_executed(self):
        detection = _false_positive(0.95)
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_fixed_response(detection, context)
        assert decision.executed_action is not None
        assert recovery_result_would_require_reinvestigation(detection, context, decision) is False

    def test_true_for_moderate_action_on_high_stakes_real_attack(self):
        detection = _attack(0.7)  # moderate confidence -> isolate_non_critical
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_fixed_response(detection, context)  # naive baseline executes unconditionally
        assert decision.executed_action == ResponseActionCategory.ISOLATE_NON_CRITICAL
        assert recovery_result_would_require_reinvestigation(detection, context, decision) is True

    def test_false_for_severe_action_on_high_stakes_real_attack(self):
        detection = _attack(0.95)  # high confidence -> shutdown
        context = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)
        decision = decide_fixed_response(detection, context)
        assert decision.executed_action == ResponseActionCategory.SHUTDOWN
        assert recovery_result_would_require_reinvestigation(detection, context, decision) is False


# --- experiment-only confidence gate ----------------------------------------

_LOW_STAKES = DeviceContext(device_criticality=DeviceCriticality.LOW, patient_dependency=False)
_HIGH_STAKES = DeviceContext(device_criticality=DeviceCriticality.HIGH, patient_dependency=True)


def _gated(detection, context, threshold):
    return decide_full_system_confidence_gated(
        detection,
        context,
        "T-gate",
        risk_model=RuleBasedRiskModel(),
        policy_engine=PolicyEngine(),
        min_autonomous_confidence=threshold,
    )


def _plain(detection, context):
    return decide_full_system(
        detection, context, "T-gate", risk_model=RuleBasedRiskModel(), policy_engine=PolicyEngine()
    )


def test_gate_sends_a_low_confidence_autonomous_action_to_approval():
    detection = _false_positive(confidence=0.7)
    assert _plain(detection, _LOW_STAKES).executed_action is not None  # would have acted alone
    gated = _gated(detection, _LOW_STAKES, 0.9)
    assert gated.executed_action is None
    assert gated.requires_human_approval is True
    assert gated.policy_rule_id == CONFIDENCE_GATE_RULE_ID


def test_gate_leaves_a_confident_detection_untouched():
    detection = _attack(confidence=0.99)
    assert _gated(detection, _LOW_STAKES, 0.9) == _plain(detection, _LOW_STAKES)


def test_gate_never_makes_a_decision_less_safe_than_full_system():
    for context in (_LOW_STAKES, _HIGH_STAKES):
        for detection in (_attack(0.65), _attack(0.99), _false_positive(0.65), _true_negative()):
            plain = _plain(detection, context)
            gated = _gated(detection, context, 0.95)
            if plain.executed_action is None:
                assert gated.executed_action is None  # gate cannot add an action
            assert not is_unsafe_autonomous_action(gated)


def test_gate_at_the_detection_threshold_is_a_no_op():
    for detection in (_attack(0.65), _false_positive(0.65)):
        assert _gated(detection, _LOW_STAKES, 0.6) == _plain(detection, _LOW_STAKES)
