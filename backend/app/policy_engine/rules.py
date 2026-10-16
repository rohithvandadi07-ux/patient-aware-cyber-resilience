"""Policy Engine rule table -- the deterministic, authoritative routing logic.

Architecture spec Section 13: no LLM call anywhere in this package. Given a
`RiskScore` and the chosen response action, decides autonomous-execution vs.
human-approval-required, with every decision naming the specific rule that
fired (`policy_rule_id`) -- "required for both the dashboard's explanation
field and for Section 18's 'unsafe response rate' evaluation metric to mean
anything."

Section 13's three stated rules, verbatim:
  1. Autonomous execution allowed: response_impact <= LOW, regardless of cyber_risk.
  2. Autonomous execution allowed only if policy conditions hold: response_impact
     == MEDIUM and device.patient_dependency == False.
  3. Human approval required: response_impact >= HIGH, OR
     device.patient_dependency == True and action category in
     {SHUTDOWN, ISOLATE_CRITICAL} -- unconditionally, regardless of cyber severity.

**The MECE gap Section 13 leaves open:** rules 1-3 do not jointly cover
response_impact == MEDIUM and patient_dependency == True and action NOT in
{SHUTDOWN, ISOLATE_CRITICAL} (e.g. a MEDIUM-impact RESTART_SERVICE on a
patient-dependent device). This case satisfies none of the three conditions
above as written. Rather than silently falling through to an unspecified
outcome, this module resolves it conservatively -- human approval required --
consistent with the architecture's overriding principle ("the most secure
cyber response is not always the safest clinical response": when a
patient-dependent device is involved and impact is not clearly low, default
to oversight). This is a deliberate gap-fill this module makes, not a fourth
rule Section 13 states -- flagged here and in the rule's own
`policy_rule_id`/rationale so it is never mistaken for literal spec text.

**Why rule 3's patient-dependency+action check is evaluated independently of
response_impact, not folded into "response_impact >= HIGH":** in practice,
`RuleBasedRiskModel` (Phase 5) already forces response_impact to HIGH/CRITICAL
for SHUTDOWN/ISOLATE_CRITICAL on a patient-dependent device, so rule 3's two
conditions are not independent in the current system -- but the Policy Engine
is "the layer agents must never be able to bypass" (Section 13) and is meant
to be the backstop of last resort, not a layer that trusts the risk engine got
it right. Checking the hard rule directly here, rather than only via
response_impact, is deliberate defense-in-depth: a future RiskModel
implementation that scored this case differently would still be caught.
"""

from app.schemas.agents import ClinicalContext
from app.schemas.enums import ImpactLevel, ResponseActionCategory
from app.schemas.risk import RiskScore

_IMPACT_ORDER: dict[ImpactLevel, int] = {
    ImpactLevel.LOW: 0,
    ImpactLevel.MEDIUM: 1,
    ImpactLevel.HIGH: 2,
    ImpactLevel.CRITICAL: 3,
}

# Section 13's literal rule 3 names exactly these two action categories --
# not "every severe-disruption action" (contrast with risk_engine/rules.py's
# broader _SEVERE_DISRUPTION_ACTIONS tier, which is a Phase 5 risk-scoring
# concern, not this Phase 6 policy-routing concern). Keeping this set narrow
# and exactly as specified is what makes this rule auditable against the
# architecture doc by direct comparison.
_UNCONDITIONAL_APPROVAL_ACTIONS = frozenset(
    {ResponseActionCategory.SHUTDOWN, ResponseActionCategory.ISOLATE_CRITICAL}
)

# Rule IDs are stable strings, not auto-generated, so a dashboard or an
# evaluation script can key off them directly and so a reviewer diffing this
# file against Section 13 can match each branch to its rule by name.
RULE_PATIENT_DEPENDENT_SEVERE_ACTION = "patient_dependent_severe_action"
RULE_AUTONOMOUS_LOW_IMPACT = "autonomous_low_impact"
RULE_AUTONOMOUS_MEDIUM_NON_DEPENDENT = "autonomous_medium_non_dependent"
RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL = "approval_medium_patient_dependent_gap_fill"
RULE_APPROVAL_HIGH_IMPACT = "approval_high_impact"
# Opt-in confidence gate (see `apply_confidence_gate`). Not part of Section 13's
# three stated rules -- an addition motivated by evaluation/real_data_comparison.md
# (about half of the real detector's false alarms still got autonomous isolation)
# and measured in evaluation/confidence_gating.md / calibrated_gating.md. The first
# id is the same string the experiment-only gate in evaluation/baseline_systems.py
# uses, so the two are directly comparable.
RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE = "approval_low_detector_confidence"
RULE_APPROVAL_UNKNOWN_DETECTOR_CONFIDENCE = "approval_unknown_detector_confidence"


def classify_routing(
    response_impact: ImpactLevel,
    patient_dependency: bool,
    action_category: ResponseActionCategory,
) -> tuple[bool, str, str]:
    """Returns (requires_human_approval, policy_rule_id, rationale).

    Evaluated in the order below; the first matching rule wins. Rule 3's
    patient-dependency+action check is checked first and unconditionally,
    exactly as Section 13 states ("unconditionally, regardless of how severe
    the cyber threat is") -- it does not merely join the response_impact
    comparison lower down, because defense-in-depth means it must not depend
    on response_impact classification succeeding correctly for this case.
    """
    if patient_dependency and action_category in _UNCONDITIONAL_APPROVAL_ACTIONS:
        return (
            True,
            RULE_PATIENT_DEPENDENT_SEVERE_ACTION,
            f"Human approval required unconditionally: patient_dependency=true and "
            f"action={action_category.value} is in the Section 13 unconditional-approval "
            "set {shutdown, isolate_critical}, regardless of response_impact or cyber_risk.",
        )

    impact_rank = _IMPACT_ORDER[response_impact]

    if impact_rank <= _IMPACT_ORDER[ImpactLevel.LOW]:
        return (
            False,
            RULE_AUTONOMOUS_LOW_IMPACT,
            f"Autonomous execution allowed: response_impact={response_impact.value} <= low, "
            "regardless of cyber_risk.",
        )

    if response_impact == ImpactLevel.MEDIUM:
        if not patient_dependency:
            return (
                False,
                RULE_AUTONOMOUS_MEDIUM_NON_DEPENDENT,
                "Autonomous execution allowed: response_impact=medium and "
                "patient_dependency=false.",
            )
        return (
            True,
            RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL,
            "Human approval required: response_impact=medium and patient_dependency=true. "
            "Section 13 does not explicitly rule on this combination (its stated rules cover "
            "response_impact<=low, response_impact==medium-with-non-dependent-device, and "
            "response_impact>=high) -- this is a deliberate conservative gap-fill, not a "
            "literal Section 13 rule, chosen because a patient-dependent device with "
            "non-trivial response impact should default to human oversight.",
        )

    # impact_rank > MEDIUM, i.e. HIGH or CRITICAL.
    return (
        True,
        RULE_APPROVAL_HIGH_IMPACT,
        f"Human approval required: response_impact={response_impact.value} >= high, "
        "regardless of cyber_risk.",
    )


def get_response_impact_for_action(
    risk_score: RiskScore, action_category: ResponseActionCategory
) -> ImpactLevel:
    """Looks up the chosen action's response_impact from a RiskScore, raising
    a clear error rather than silently defaulting to LOW (or any other value)
    if that action was never actually scored -- an unscored action is a bug
    upstream (the Risk Engine should have scored every candidate under
    consideration), not something this module papers over.
    """
    try:
        return risk_score.response_impact[action_category.value]
    except KeyError as exc:
        raise ValueError(
            f"RiskScore for incident {risk_score.incident_id!r} has no response_impact entry "
            f"for action {action_category.value!r} -- it must be scored by the Risk Engine "
            "before the Policy Engine can route it."
        ) from exc


def decide_routing(
    risk_score: RiskScore, context: ClinicalContext, action_category: ResponseActionCategory
) -> tuple[bool, str, str]:
    """Convenience wrapper: looks up response_impact from the RiskScore, then
    classifies routing. Returns the same (requires_human_approval,
    policy_rule_id, rationale) tuple as `classify_routing`.
    """
    response_impact = get_response_impact_for_action(risk_score, action_category)
    return classify_routing(response_impact, context.patient_dependency, action_category)


def apply_confidence_gate(
    routing: tuple[bool, str, str],
    detection_confidence: float | None,
    min_autonomous_confidence: float | None,
) -> tuple[bool, str, str]:
    """Optional extra gate on top of `classify_routing`.

    Only ever turns an *autonomous* decision into a human-approval one; it can
    never make a decision less safe. Disabled (returns `routing` unchanged)
    when `min_autonomous_confidence` is None, which is the default, so the
    engine's behavior is exactly Section 13's unless an operator opts in.

    When enabled and the detector's confidence is not supplied, the decision
    fails closed to human approval: an unknown confidence cannot be vouched
    for, the same fail-closed stance as auth with no keys configured.
    """
    requires_approval, rule_id, rationale = routing
    if min_autonomous_confidence is None or requires_approval:
        return routing
    if detection_confidence is None:
        return (
            True,
            RULE_APPROVAL_UNKNOWN_DETECTOR_CONFIDENCE,
            "Human approval required: the confidence gate is enabled "
            f"(min_autonomous_confidence={min_autonomous_confidence}) but no detector confidence "
            f"was supplied, so autonomy cannot be granted. Would otherwise have been: {rule_id}.",
        )
    if detection_confidence < min_autonomous_confidence:
        return (
            True,
            RULE_APPROVAL_LOW_DETECTOR_CONFIDENCE,
            f"Human approval required: detector confidence {detection_confidence:.3f} is below "
            f"the autonomous-action minimum {min_autonomous_confidence}. Would otherwise have "
            f"been: {rule_id}.",
        )
    return routing
