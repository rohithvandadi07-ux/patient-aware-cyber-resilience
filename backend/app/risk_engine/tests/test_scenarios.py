"""Section 17's Scenario A and B, exercised at the risk-engine level.

These are the Phase 5 gate per Section 19: "`RuleBasedRiskModel` passes
Scenario A and B from Section 17." Scope note: Section 17 describes each
scenario end-to-end (detection -> agents -> risk -> policy -> response ->
recovery -> blockchain), but the Policy Engine (Phase 6), Response
Orchestrator (Phase 6/7), and blockchain provenance (Phase 8) don't exist
yet. What IS testable now, and what these tests actually assert, is the part
Phase 5 owns: given the clinical/cyber inputs each scenario describes, does
`RuleBasedRiskModel` produce a `RiskScore` whose `response_impact` values are
exactly what a correct Policy Engine would need to reach each scenario's
documented outcome? Full end-to-end Scenario A/B tests (the actual detection
-> ... -> blockchain chain) belong in top-level `tests/` once Phase 6-8 exist
to run them against.
"""

from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    ResponseActionCategory,
)

_IMPACT_ORDER = {ImpactLevel.LOW: 0, ImpactLevel.MEDIUM: 1, ImpactLevel.HIGH: 2, ImpactLevel.CRITICAL: 3}


# --- Scenario A: non-critical device compromised -------------------------
#
# "a simulated infusion pump (criticality=low, patient_dependency=false) hit
# with a scripted DoS scenario. Expected: [...] Policy Engine auto-approves
# network isolation [...] Assertion: no human-approval step was required, and
# the chosen action was not a shutdown."
#
# Section 13's Policy Engine rule table (once built) auto-approves whenever
# response_impact <= LOW regardless of cyber_risk. For that to produce the
# documented outcome, isolate_non_critical must score <= LOW here, and
# shutdown must score strictly higher than isolate_non_critical so a Policy
# Engine comparing candidates would never prefer it anyway.


def _scenario_a_threat() -> ThreatAssessment:
    return ThreatAssessment(
        incident_id="scenario-a",
        attack_type=AttackCategory.DOS,
        severity=ImpactLevel.HIGH,
        confidence=0.9,
        propagation_risk=ImpactLevel.LOW,
        reasoning_summary="DoS flood pattern against infusion-pump-01's network interface.",
    )


def _scenario_a_context() -> ClinicalContext:
    return ClinicalContext(
        incident_id="scenario-a",
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )


def test_scenario_a_isolation_scores_low_enough_for_auto_approval():
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(
            action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL,
            description="Isolate infusion-pump-01's network segment",
        ),
        CandidateAction(
            action_category=ResponseActionCategory.SHUTDOWN,
            description="Shut down infusion-pump-01",
        ),
    ]

    result = model.calculate_risk(_scenario_a_threat(), _scenario_a_context(), actions)

    assert result.response_impact["isolate_non_critical"] == ImpactLevel.LOW


def test_scenario_a_shutdown_scores_higher_impact_than_isolation():
    # Even though Section 17 says the Policy Engine should route on
    # response_impact rather than the agent's raw recommendation, a risk
    # engine that scored shutdown no worse than isolation on a low-stakes
    # device would give a downstream agent no reason to prefer the gentler
    # action -- the two must be distinguishable.
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="a"),
        CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="b"),
    ]

    result = model.calculate_risk(_scenario_a_threat(), _scenario_a_context(), actions)

    isolate_rank = _IMPACT_ORDER[result.response_impact["isolate_non_critical"]]
    shutdown_rank = _IMPACT_ORDER[result.response_impact["shutdown"]]
    assert shutdown_rank > isolate_rank


def test_scenario_a_high_cyber_severity_does_not_override_low_clinical_response_impact():
    # The DoS threat is rated HIGH severity (Section 17's own description:
    # "hit with a scripted DoS scenario" is treated seriously as an attack),
    # but because the device is non-critical and non-dependent, isolation's
    # response_impact must stay LOW regardless -- response_impact tracks
    # clinical context, not cyber severity, by design (Section 12).
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL, description="a")]

    result = model.calculate_risk(_scenario_a_threat(), _scenario_a_context(), actions)

    assert result.cyber_risk > 0.5  # the threat itself is genuinely scored as serious
    assert result.response_impact["isolate_non_critical"] == ImpactLevel.LOW


# --- Scenario B: patient-dependent ventilator compromised ----------------
#
# "a simulated ventilator (criticality=high, patient_dependency=true) hit
# with a scripted command-injection scenario. Expected: [...] Policy Engine
# forces requires_human_approval=true even though the Threat Reasoning Agent
# rates cyber severity as critical [...] Assertion: the system never
# autonomously shuts down a patient-dependent, high-criticality device,
# regardless of attack severity -- this is the one assertion that most
# directly tests the central research claim, so it gets the most scrutiny of
# any test in the suite."
#
# At the risk-engine level: shutdown (and isolate_critical) must score
# CRITICAL impact regardless of how severe the cyber threat is scored, which
# is exactly what forces Section 13's Policy Engine to require human
# approval unconditionally. A safer alternative must score lower, so there
# is a real non-shutdown option for the Response Planning Agent to prefer.


def _scenario_b_threat(
    severity: ImpactLevel = ImpactLevel.CRITICAL, confidence: float = 0.95
) -> ThreatAssessment:
    return ThreatAssessment(
        incident_id="scenario-b",
        attack_type=AttackCategory.MITM_INJECTION,
        severity=severity,
        confidence=confidence,
        propagation_risk=ImpactLevel.HIGH,
        reasoning_summary="Command-injection pattern targeting ventilator-01's control interface.",
    )


def _scenario_b_context() -> ClinicalContext:
    return ClinicalContext(
        incident_id="scenario-b",
        device_criticality=DeviceCriticality.HIGH,
        patient_dependency=True,
        clinical_impact_level=ImpactLevel.CRITICAL,
        safety_constraints=["ventilator must not be powered off while patient_dependency is true"],
    )


def test_scenario_b_shutdown_is_forced_critical_despite_critical_cyber_severity():
    # This is the test Section 17 says gets "the most scrutiny of any test
    # in the suite" -- the central research claim in its most direct form.
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="Power off")]

    result = model.calculate_risk(_scenario_b_threat(), _scenario_b_context(), actions)

    assert result.cyber_risk > 0.8  # the threat is genuinely scored as near-maximal
    assert result.response_impact["shutdown"] == ImpactLevel.CRITICAL


def test_scenario_b_isolate_critical_is_also_forced_critical():
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(action_category=ResponseActionCategory.ISOLATE_CRITICAL, description="Isolate")
    ]

    result = model.calculate_risk(_scenario_b_threat(), _scenario_b_context(), actions)

    assert result.response_impact["isolate_critical"] == ImpactLevel.CRITICAL


def test_scenario_b_forces_critical_regardless_of_cyber_severity_level():
    # "regardless of attack severity" -- not just at the one severity level
    # the scenario happens to script. Re-run across every severity.
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="Power off")]

    for severity in (ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL):
        result = model.calculate_risk(_scenario_b_threat(severity=severity), _scenario_b_context(), actions)
        assert result.response_impact["shutdown"] == ImpactLevel.CRITICAL, (
            f"shutdown must stay CRITICAL impact at severity={severity.value}"
        )


def test_scenario_b_forces_critical_regardless_of_confidence_level():
    # "regardless of attack severity" extends naturally to confidence too --
    # a Threat Reasoning Agent that is only 10% confident in a critical
    # assessment must not let shutdown's clinical impact drop.
    model = RuleBasedRiskModel()
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="Power off")]

    for confidence in (0.1, 0.5, 0.95):
        result = model.calculate_risk(
            _scenario_b_threat(confidence=confidence), _scenario_b_context(), actions
        )
        assert result.response_impact["shutdown"] == ImpactLevel.CRITICAL


def test_scenario_b_offers_a_safer_action_that_scores_lower_than_shutdown():
    # "a safer non-shutdown action is proposed" -- the risk engine must make
    # at least one real alternative visibly preferable, not just confirm
    # shutdown is bad with no escape route.
    model = RuleBasedRiskModel()
    actions = [
        CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="Power off"),
        CandidateAction(
            action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL,
            description="Isolate the ventilator's non-critical telemetry channel",
        ),
        CandidateAction(
            action_category=ResponseActionCategory.ROTATE_CREDENTIALS,
            description="Rotate the compromised credentials",
        ),
    ]

    result = model.calculate_risk(_scenario_b_threat(), _scenario_b_context(), actions)

    shutdown_rank = _IMPACT_ORDER[result.response_impact["shutdown"]]
    isolate_rank = _IMPACT_ORDER[result.response_impact["isolate_non_critical"]]
    rotate_rank = _IMPACT_ORDER[result.response_impact["rotate_credentials"]]
    assert isolate_rank < shutdown_rank
    assert rotate_rank < shutdown_rank


def test_scenario_b_clinical_risk_reflects_patient_dependency_even_at_low_cyber_risk():
    # Demonstrates the dual-risk engine's core design point directly: even if
    # cyber_risk were low, clinical_risk for this device must still be high
    # due to patient dependency -- the two are genuinely independent axes,
    # not one driving the other.
    model = RuleBasedRiskModel()
    low_severity_threat = _scenario_b_threat(severity=ImpactLevel.LOW, confidence=0.3)
    actions = [CandidateAction(action_category=ResponseActionCategory.SHUTDOWN, description="a")]

    result = model.calculate_risk(low_severity_threat, _scenario_b_context(), actions)

    assert result.cyber_risk < 0.3
    assert result.clinical_risk >= 0.55  # the patient-dependency floor from rules.py
    assert result.response_impact["shutdown"] == ImpactLevel.CRITICAL
