import pytest

from app.evaluation.baseline_systems import (
    DetectionOutcome,
    DeviceContext,
    SystemName,
    decide_detection_only,
    decide_fixed_response,
    decide_full_system,
    detection_outcome_from_row,
    is_high_stakes,
    is_unnecessary_isolation,
    is_unsafe_autonomous_action,
    propose_action,
    sample_device_contexts,
)
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.enums import DeviceCriticality, ResponseActionCategory


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
