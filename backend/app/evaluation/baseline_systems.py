"""Phase 13 -- the three response "systems" compared at scale.

Architecture spec Section 18 adopts the brief's five-system baseline
progression (detection-only -> detection+fixed-response -> detection+agentic
AI -> detection+risk-engine -> full patient-aware system) and Section 19's
Phase 13 gate requires "at least the detection-only vs. full-system baseline
comparison" to have real, reported numbers. This module implements that
comparison's decision logic for three of the five systems, holding every
other variable fixed across them so the only thing that differs is each
system's response-decision step:

  - ``detection_only``: no response layer exists at all. Included for
    completeness and because the gate names it explicitly, but its
    patient-safety metrics are trivially zero by construction (a system that
    never responds can never produce an unsafe autonomous response or an
    unnecessary isolation) -- documented here, not silently presented as if
    it were a meaningful zero.
  - ``fixed_response``: a naive, non-patient-aware policy. Whatever action
    ``propose_action`` recommends is executed immediately and
    unconditionally, with no risk assessment and no approval gate at all.
    This is the architecture's second named system ("detection + fixed
    response") -- needed here, not invented scope, because without it the
    "detection-only vs. full-system" comparison the gate asks for would have
    nothing non-trivial on the naive side to contrast against.
  - ``full_system``: the real, already-shipped ``RuleBasedRiskModel`` (Phase
    5) and ``PolicyEngine`` (Phase 6) decide whether the same proposed action
    may execute autonomously or must wait for a human.

What is mocked, and why, disclosed up front: there is still no real LLM
backend anywhere in this codebase (an open decision since Phase 4, unchanged
by every phase since). The Threat Reasoning Agent, Healthcare Context Agent,
and Response Planning Agent are therefore stood in for by the small,
deterministic, explicitly-named functions below -- each one an honest,
disclosed restatement of a scenario's real ground-truth parameters (the
trained detector's real predicted label/confidence; the device context's
real, randomly-sampled criticality/patient-dependency), never an arbitrary
or hand-tuned value chosen to make a particular result look better. This is
the same disclosed simplification every prior phase has made in the same
place (Phase 10's dashboard, Phase 11's E2E seeding) -- see those phases'
README sections for the same rationale restated.

What is real: the detector's predictions come from Phase 3's actual trained
model, scored on its actual held-out test split (see
``run_baseline_comparison.py``). The risk/policy decision for ``full_system``
is made by the real ``RuleBasedRiskModel`` and ``PolicyEngine`` classes --
this module calls them, it does not reimplement or approximate their rules.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum

from app.cybersecurity.detection_service import DEFAULT_CONFIDENCE_THRESHOLD, DetectionService
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.enums import AttackCategory, DeviceCriticality, ImpactLevel, ResponseActionCategory

_BENIGN_LABEL = AttackCategory.UNKNOWN.value

# The two actions `propose_action` ever recommends -- deliberately the two
# used by Section 17's own Scenario A (a moderate, non-severe isolation) and
# Scenario B (the most severe action the orchestrator can execute), so this
# experiment stresses the policy layer with the same adversarial choice the
# architecture's own hand-written scenarios already use, not a softer one
# that would make every system look safe by construction.
_SEVERE_ACTION = ResponseActionCategory.SHUTDOWN
_MODERATE_ACTION = ResponseActionCategory.ISOLATE_NON_CRITICAL

# Response-impact tiers a disruptive action can fall into -- mirrors
# app/risk_engine/rules.py's own `_SEVERE_DISRUPTION_ACTIONS` /
# `_MODERATE_DISRUPTION_ACTIONS` partition exactly (duplicated as a small,
# named constant here rather than imported, since those names are
# module-private to risk_engine/rules.py and this module only needs to know
# whether `_SEVERE_ACTION`/`_MODERATE_ACTION` specifically count as
# "disruptive" for the unnecessary-isolation metric, not the full partition).
_DISRUPTIVE_ACTIONS = frozenset({_SEVERE_ACTION, _MODERATE_ACTION})


class SystemName(StrEnum):
    DETECTION_ONLY = "detection_only"
    FIXED_RESPONSE = "fixed_response"
    FULL_SYSTEM = "full_system"


@dataclass(frozen=True)
class DeviceContext:
    """One randomly-sampled device context for a trial -- stands in for what
    the Healthcare Context Agent would have reported, built honestly from
    sampled ground truth rather than invented per trial."""

    device_criticality: DeviceCriticality
    patient_dependency: bool


@dataclass(frozen=True)
class DetectionOutcome:
    """What the real trained detector actually produced for one held-out test
    row -- `ground_truth_label` is the row's real label; `fired` mirrors
    `DetectionService.score_window`'s own suppression contract (confidence
    below threshold, or a benign prediction, never produces a detection)."""

    ground_truth_label: str
    predicted_label: str
    confidence: float
    fired: bool

    @property
    def ground_truth_is_attack(self) -> bool:
        return self.ground_truth_label != _BENIGN_LABEL

    @property
    def is_false_positive(self) -> bool:
        """Detector fired, but the row's real label was benign."""
        return self.fired and not self.ground_truth_is_attack


@dataclass(frozen=True)
class SystemDecision:
    """One system's response decision for one trial. `executed_action` is
    `None` whenever that system takes no autonomous action this trial --
    either because no detection fired, because the system has no response
    layer at all (`detection_only`), or because `full_system`'s Policy
    Engine required human approval that, in a batch experiment with no human
    in the loop, is never granted (matching the real system's own behavior:
    an incident awaiting approval does not execute)."""

    system: SystemName
    detection: DetectionOutcome
    context: DeviceContext
    proposed_action: ResponseActionCategory | None
    requires_human_approval: bool | None  # None when not applicable (detection_only, or no detection)
    executed_action: ResponseActionCategory | None
    policy_rule_id: str | None = None


def sample_device_contexts(n: int, seed: int) -> list[DeviceContext]:
    """`n` device contexts, uniformly sampled over the 3x2 criticality x
    patient-dependency space, independent of any attack label -- an
    attacker targeting a hospital network has no reason to only ever hit
    low-criticality devices, so context is deliberately not correlated with
    which row of the detector's test set it gets paired with (see
    `run_baseline_comparison.py`). Same seed -> same sequence, every run,
    consistent with every other scenario-generation seed in this codebase
    (Section 9's `ScenarioRunner`)."""
    rng = random.Random(seed)
    criticalities = list(DeviceCriticality)
    contexts = []
    for _ in range(n):
        contexts.append(
            DeviceContext(
                device_criticality=rng.choice(criticalities),
                patient_dependency=rng.choice([True, False]),
            )
        )
    return contexts


def detection_outcome_from_row(
    ground_truth_label: str,
    predicted_label: str,
    confidence: float,
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> DetectionOutcome:
    """Applies the real runtime suppression rule
    (`DetectionService.score_window`'s contract: a benign prediction, or one
    below the confidence threshold, never becomes a detection) to one
    already-scored held-out test row."""
    fired = predicted_label != _BENIGN_LABEL and confidence >= confidence_threshold
    return DetectionOutcome(
        ground_truth_label=ground_truth_label,
        predicted_label=predicted_label,
        confidence=confidence,
        fired=fired,
    )


def propose_action(detection: DetectionOutcome) -> ResponseActionCategory:
    """Disclosed stand-in for the Response Planning Agent (no real LLM
    backend -- see module docstring): recommends the single most severe
    action the simulator's orchestrator can execute (`shutdown`) when the
    detector's own confidence clears the high-confidence cutoff
    (`DetectionService._severity_hint`'s `CRITICAL` threshold, reused here
    rather than re-picking a different number), and a moderate action
    (`isolate_non_critical`) otherwise. Only ever called when `detection.fired`
    is true."""
    severity = DetectionService._severity_hint(detection.confidence)
    return _SEVERE_ACTION if severity == ImpactLevel.CRITICAL else _MODERATE_ACTION


def clinical_context_for(incident_id: str, device: DeviceContext) -> ClinicalContext:
    """Disclosed stand-in for the Healthcare Context Agent: `clinical_impact_level`
    has no ground-truth source of its own in this project (no real clinical
    simulation exists), so it is derived, honestly and simply, from the two
    fields that do have ground truth -- never an independent arbitrary value.
    Patient-dependent devices are always scored at least HIGH clinical impact;
    otherwise a HIGH-criticality device scores MEDIUM and anything else LOW."""
    if device.patient_dependency:
        impact = ImpactLevel.HIGH
    elif device.device_criticality == DeviceCriticality.HIGH:
        impact = ImpactLevel.MEDIUM
    else:
        impact = ImpactLevel.LOW
    return ClinicalContext(
        incident_id=incident_id,
        device_criticality=device.device_criticality,
        patient_dependency=device.patient_dependency,
        clinical_impact_level=impact,
    )


def threat_assessment_for(incident_id: str, detection: DetectionOutcome) -> ThreatAssessment:
    """Disclosed stand-in for the Threat Reasoning Agent: every field here is
    read directly off the real detector's own output for this row (predicted
    label, confidence, the same severity-hint rule the live system uses) --
    not invented reasoning. `propagation_risk` has no independent
    ground-truth source either, so it is set equal to `severity`, the same
    kind of disclosed simplification as `clinical_context_for`."""
    severity = DetectionService._severity_hint(detection.confidence)
    try:
        attack_type = AttackCategory(detection.predicted_label)
    except ValueError:
        attack_type = AttackCategory.UNKNOWN
    return ThreatAssessment(
        incident_id=incident_id,
        attack_type=attack_type,
        severity=severity,
        confidence=detection.confidence,
        propagation_risk=severity,
        reasoning_summary=(
            f"Phase 13 evaluation stand-in: detector predicted {attack_type.value!r} at "
            f"confidence {detection.confidence:.3f} (no real LLM reasoning -- see module docstring)."
        ),
    )


def decide_detection_only(detection: DetectionOutcome, context: DeviceContext) -> SystemDecision:
    """No response layer exists -- this system only ever detects."""
    return SystemDecision(
        system=SystemName.DETECTION_ONLY,
        detection=detection,
        context=context,
        proposed_action=None,
        requires_human_approval=None,
        executed_action=None,
    )


def decide_fixed_response(detection: DetectionOutcome, context: DeviceContext) -> SystemDecision:
    """Naive policy: whatever `propose_action` recommends executes
    immediately, unconditionally, the moment a detection fires -- no risk
    scoring, no approval gate, no awareness of `context` at all."""
    if not detection.fired:
        return SystemDecision(
            system=SystemName.FIXED_RESPONSE,
            detection=detection,
            context=context,
            proposed_action=None,
            requires_human_approval=None,
            executed_action=None,
        )
    action = propose_action(detection)
    return SystemDecision(
        system=SystemName.FIXED_RESPONSE,
        detection=detection,
        context=context,
        proposed_action=action,
        requires_human_approval=False,
        executed_action=action,
    )


def decide_full_system(
    detection: DetectionOutcome,
    context: DeviceContext,
    incident_id: str,
    *,
    risk_model: RuleBasedRiskModel,
    policy_engine: PolicyEngine,
) -> SystemDecision:
    """The real Risk Engine (Phase 5) and Policy Engine (Phase 6) decide
    whether the same proposed action executes autonomously. When the Policy
    Engine requires human approval, `executed_action` is `None` -- there is
    no human in this batch experiment to approve it, exactly as the real
    system would also leave it `awaiting_approval` rather than executing."""
    if not detection.fired:
        return SystemDecision(
            system=SystemName.FULL_SYSTEM,
            detection=detection,
            context=context,
            proposed_action=None,
            requires_human_approval=None,
            executed_action=None,
        )

    action = propose_action(detection)
    threat = threat_assessment_for(incident_id, detection)
    clinical_context = clinical_context_for(incident_id, context)

    risk_score = risk_model.calculate_risk(
        threat,
        clinical_context,
        [CandidateAction(action_category=action, description="Phase 13 evaluation candidate")],
    )
    decision = policy_engine.evaluate_action(risk_score, clinical_context, action)

    return SystemDecision(
        system=SystemName.FULL_SYSTEM,
        detection=detection,
        context=context,
        proposed_action=action,
        requires_human_approval=decision.requires_human_approval,
        executed_action=None if decision.requires_human_approval else action,
        policy_rule_id=decision.policy_rule_id,
    )


def is_high_stakes(context: DeviceContext) -> bool:
    """HIGH-criticality and patient-dependent -- the exact combination
    Section 13's rule 3 and Scenario B both single out as the one where an
    autonomous severe action would be clinically dangerous."""
    return context.device_criticality == DeviceCriticality.HIGH and context.patient_dependency


def is_unsafe_autonomous_action(decision: SystemDecision) -> bool:
    """An executed (autonomous, unapproved) action, on a real attack, in a
    high-stakes context, where the action taken is one of the two disruptive
    categories this experiment ever proposes. `requires_human_approval` is
    checked explicitly (not inferred from `executed_action is not None`) so
    a future system variant that executes without ever setting that field
    cannot silently read as "safe" here."""
    return (
        decision.executed_action is not None
        and decision.requires_human_approval is not True
        and decision.detection.ground_truth_is_attack
        and is_high_stakes(decision.context)
        and decision.executed_action in _DISRUPTIVE_ACTIONS
    )


def is_unnecessary_isolation(decision: SystemDecision) -> bool:
    """An executed (autonomous, unapproved) disruptive action taken on a
    false positive -- a real attack was never present, so any disruption
    caused was, by definition, unnecessary."""
    return (
        decision.executed_action is not None
        and decision.requires_human_approval is not True
        and decision.detection.is_false_positive
        and decision.executed_action in _DISRUPTIVE_ACTIONS
    )
