"""RuleBasedRiskModel's rule tables -- explicit, named, testable functions.

Architecture spec Section 12: "`RuleBasedRiskModel`: an explicit, documented
table, not a trained model [...] intentionally simple: it is auditable,
explainable on the dashboard [...] and gives later work something concrete to
beat." Every rule below is its own named function specifically so each one is
independently unit-testable (Section 5.7's branch-coverage goal) and so the
`explanation` field assembled in `model.py`/`rule_based.py` can name exactly
which rule fired, not just the outcome -- the same transparency principle
Section 13 states for the Policy Engine ("every policy decision is logged
with the specific rule that fired, not just the outcome").
"""

from app.schemas.agents import ClinicalContext, ThreatAssessment
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory

# Base cyber-risk score per severity level, before confidence scaling.
# Deliberately not linear (0.0/0.33/0.67/1.0) -- a CRITICAL-severity threat
# the agent is only moderately confident about should still register as more
# dangerous than a LOW-severity threat the agent is fully confident about, so
# CRITICAL's base is set high enough that even a partial confidence scaling
# keeps it above LOW/MEDIUM's maximum.
_SEVERITY_BASE_CYBER_RISK: dict[ImpactLevel, float] = {
    ImpactLevel.LOW: 0.15,
    ImpactLevel.MEDIUM: 0.40,
    ImpactLevel.HIGH: 0.70,
    ImpactLevel.CRITICAL: 0.90,
}


def score_cyber_risk(threat: ThreatAssessment) -> tuple[float, str]:
    """cyber_risk = severity's base score, scaled by the Threat Reasoning
    Agent's own stated confidence -- a threat assessment the agent is unsure
    about should not drive risk as hard as one it is confident about, but the
    severity level still sets the ceiling. Returns (score, rule explanation).
    """
    base = _SEVERITY_BASE_CYBER_RISK[threat.severity]
    # Floor the confidence scaling at 0.5 rather than letting it go to zero:
    # even a low-confidence CRITICAL/HIGH assessment should not be scored as
    # near-zero risk -- an agent that is uncertain about a severe threat is
    # not the same as an agent confidently reporting a benign one, and
    # treating them the same would understate risk in exactly the case where
    # caution matters most.
    scaling = 0.5 + 0.5 * threat.confidence
    score = round(base * scaling, 4)
    explanation = (
        f"cyber_risk={score}: base {base} for severity={threat.severity.value}, "
        f"scaled by confidence={threat.confidence:.2f} (floor 0.5 scaling)"
    )
    return score, explanation


# Base clinical-risk score per device criticality, before patient-dependency
# and clinical-impact adjustments.
_CRITICALITY_BASE_CLINICAL_RISK: dict[DeviceCriticality, float] = {
    DeviceCriticality.LOW: 0.10,
    DeviceCriticality.MEDIUM: 0.35,
    DeviceCriticality.HIGH: 0.60,
}

# Additive bump per clinical_impact_level, layered on top of the criticality
# base -- a HIGH-criticality device the Healthcare Context Agent also flags
# as CRITICAL clinical impact right now should score higher than one merely
# flagged HIGH impact, even though both share the same device criticality.
_IMPACT_CLINICAL_RISK_BUMP: dict[ImpactLevel, float] = {
    ImpactLevel.LOW: 0.0,
    ImpactLevel.MEDIUM: 0.05,
    ImpactLevel.HIGH: 0.15,
    ImpactLevel.CRITICAL: 0.25,
}

# Patient-dependency floor: this is the literal implementation of the
# project's central claim ("the most secure cyber response is not always the
# safest clinical response") at the clinical_risk level -- a device a patient
# currently depends on must never score low clinical risk, regardless of how
# the other factors land, because the floor is what the Policy Engine's
# downstream human-approval rule (Section 13) will key off of.
_PATIENT_DEPENDENCY_CLINICAL_RISK_FLOOR = 0.55


def score_clinical_risk(context: ClinicalContext) -> tuple[float, str]:
    """clinical_risk = device criticality's base score + a clinical-impact
    bump, floored at `_PATIENT_DEPENDENCY_CLINICAL_RISK_FLOOR` whenever
    `patient_dependency` is true. Returns (score, rule explanation)."""
    base = _CRITICALITY_BASE_CLINICAL_RISK[context.device_criticality]
    bump = _IMPACT_CLINICAL_RISK_BUMP[context.clinical_impact_level]
    raw_score = base + bump

    if context.patient_dependency and raw_score < _PATIENT_DEPENDENCY_CLINICAL_RISK_FLOOR:
        score = _PATIENT_DEPENDENCY_CLINICAL_RISK_FLOOR
        explanation = (
            f"clinical_risk={score}: patient_dependency=true floor applied "
            f"(raw {base} criticality base + {bump} impact bump = {round(raw_score, 4)}, "
            f"below floor {_PATIENT_DEPENDENCY_CLINICAL_RISK_FLOOR})"
        )
    else:
        score = round(raw_score, 4)
        explanation = (
            f"clinical_risk={score}: {base} criticality={context.device_criticality.value} base "
            f"+ {bump} clinical_impact_level={context.clinical_impact_level.value} bump"
            + (", patient_dependency=true (already above floor)" if context.patient_dependency else "")
        )

    return min(score, 1.0), explanation


# Action categories that directly and severely disrupt a device's operation
# -- these are the ones Section 12's example rule names explicitly
# ("SHUTDOWN"), extended here to the other categories that have the same
# device-disrupting character (isolating critical traffic can functionally
# cut off a patient-dependent device's monitoring/control path just as
# shutdown does, even though it isn't literally powering the device off).
_SEVERE_DISRUPTION_ACTIONS = frozenset(
    {
        ResponseActionCategory.SHUTDOWN,
        ResponseActionCategory.ISOLATE_CRITICAL,
        ResponseActionCategory.QUARANTINE_SEGMENT,
        ResponseActionCategory.FAILOVER,
    }
)

# Action categories that are disruptive but recoverable/partial -- isolating
# only non-critical traffic, restricting (not cutting) communication, or
# restarting a service are meaningfully less disruptive than the categories
# above, but still more than a non-disruptive credential/session action.
_MODERATE_DISRUPTION_ACTIONS = frozenset(
    {
        ResponseActionCategory.ISOLATE_NON_CRITICAL,
        ResponseActionCategory.RESTRICT_COMMUNICATION,
        ResponseActionCategory.RESTART_SERVICE,
        ResponseActionCategory.BLOCK_TRAFFIC,
    }
)

# Action categories that never touch the device's own operation -- credential
# rotation, session revocation, activating a backup -- these act on identity
# or redundancy, not on the device the patient depends on.
_NON_DISRUPTIVE_ACTIONS = frozenset(
    {
        ResponseActionCategory.ROTATE_CREDENTIALS,
        ResponseActionCategory.REVOKE_SESSION,
        ResponseActionCategory.ACTIVATE_BACKUP,
    }
)

assert _SEVERE_DISRUPTION_ACTIONS | _MODERATE_DISRUPTION_ACTIONS | _NON_DISRUPTIVE_ACTIONS == set(
    ResponseActionCategory
), "every ResponseActionCategory must be classified into exactly one disruption tier"


def score_response_impact(
    action_category: ResponseActionCategory, context: ClinicalContext
) -> tuple[ImpactLevel, str]:
    """Per-action response_impact: how clinically disruptive this specific
    action would be on this specific device right now. This is the literal
    implementation of Section 12's example rule: "device.criticality == HIGH
    and device.patient_dependency and action.category == SHUTDOWN ->
    response_impact = CRITICAL regardless of cyber_risk" -- extended to every
    action category and every criticality/dependency combination, not just
    the one example.
    """
    high_criticality_dependent = (
        context.device_criticality == DeviceCriticality.HIGH and context.patient_dependency
    )

    if action_category in _SEVERE_DISRUPTION_ACTIONS:
        if high_criticality_dependent:
            return ImpactLevel.CRITICAL, (
                f"response_impact=critical for {action_category.value}: severe-disruption action "
                "on a HIGH-criticality, patient-dependent device, forced regardless of cyber_risk "
                "(Section 12's rule)"
            )
        if context.patient_dependency:
            return ImpactLevel.HIGH, (
                f"response_impact=high for {action_category.value}: severe-disruption action on a "
                f"patient-dependent device (criticality={context.device_criticality.value}, below "
                "HIGH so not forced to critical)"
            )
        return ImpactLevel.MEDIUM, (
            f"response_impact=medium for {action_category.value}: severe-disruption action on a "
            "non-patient-dependent device"
        )

    if action_category in _MODERATE_DISRUPTION_ACTIONS:
        if high_criticality_dependent:
            return ImpactLevel.HIGH, (
                f"response_impact=high for {action_category.value}: moderate-disruption action on a "
                "HIGH-criticality, patient-dependent device"
            )
        if context.patient_dependency:
            return ImpactLevel.MEDIUM, (
                f"response_impact=medium for {action_category.value}: moderate-disruption action on "
                f"a patient-dependent device (criticality={context.device_criticality.value})"
            )
        return ImpactLevel.LOW, (
            f"response_impact=low for {action_category.value}: moderate-disruption action on a "
            "non-patient-dependent device"
        )

    # _NON_DISRUPTIVE_ACTIONS: never touches the device's own operation, so
    # patient dependency does not escalate it the way it does above -- the
    # action simply does not create the clinical exposure those rules guard
    # against. Still bumped to MEDIUM (never LOW) on a HIGH-criticality
    # dependent device purely out of caution for second-order effects (e.g.
    # a credential rotation that briefly interrupts an authenticated session
    # the device relies on), never claimed as a measured effect.
    if high_criticality_dependent:
        return ImpactLevel.MEDIUM, (
            f"response_impact=medium for {action_category.value}: non-disruptive action, but "
            "bumped from low as a caution margin on a HIGH-criticality, patient-dependent device "
            "(possible second-order effects, not a measured one)"
        )
    return ImpactLevel.LOW, (
        f"response_impact=low for {action_category.value}: non-disruptive action "
        "(credential/session/backup-only, no device operation touched)"
    )
