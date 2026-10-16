"""Phase 13 -- the five response "systems" (and six ablations) compared at scale.

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

Extended for the architecture spec's full Section 18 progression (five named
systems, not just three) and its six "without-X" ablations:

  - ``detection_plus_agentic_ai``: runs the same disclosed agent stand-ins as
    ``full_system`` (``threat_assessment_for``, ``clinical_context_for``) to
    get a reasoned threat/clinical read on the incident, but then picks
    whether to execute via a simple, explicitly-named heuristic over those
    two outputs (see ``decide_detection_plus_agentic_ai``) instead of calling
    ``RuleBasedRiskModel``/``PolicyEngine`` at all. This is the architecture's
    third named system ("detection + Agentic AI") -- agent reasoning without
    the deterministic risk/policy backstop.
  - ``detection_plus_risk_engine``: the inverse -- skips the agent layer
    entirely (no ``clinical_context_for`` call; a fixed stub
    ``ClinicalContext`` stands in for it, deliberately blind to the trial's
    real device context) and feeds the detector's output straight into the
    real ``RuleBasedRiskModel``/``PolicyEngine``. This is the architecture's
    fourth named system ("detection + deterministic risk engine").
  - Six ablations of ``full_system`` (``decide_full_system_variant`` and the
    two functions it reuses): ``without_healthcare_context``,
    ``without_clinical_criticality``, ``without_response_impact_assessment``,
    ``without_agentic_ai``, ``without_blockchain``,
    ``without_recovery_verification``. Each genuinely disables the named
    component rather than only renaming an unchanged computation -- see each
    function's own docstring for exactly what is turned off and why, and
    ``run_baseline_comparison.py`` / ``evaluation/phase13_baseline_comparison.md``
    for the real, measured effect of each.
"""

from __future__ import annotations

import dataclasses
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
    DETECTION_PLUS_AGENTIC_AI = "detection_plus_agentic_ai"
    DETECTION_PLUS_RISK_ENGINE = "detection_plus_risk_engine"
    FULL_SYSTEM = "full_system"


class AblationName(StrEnum):
    """The six "without-X" ablations Section 18 names, each a genuine variant
    of the ``full_system`` trial path with exactly one named component turned
    off (see ``decide_full_system_variant`` and the two functions it reuses
    for ``WITHOUT_AGENTIC_AI``/``WITHOUT_BLOCKCHAIN``)."""

    WITHOUT_HEALTHCARE_CONTEXT = "without_healthcare_context"
    WITHOUT_CLINICAL_CRITICALITY = "without_clinical_criticality"
    WITHOUT_RESPONSE_IMPACT_ASSESSMENT = "without_response_impact_assessment"
    WITHOUT_AGENTIC_AI = "without_agentic_ai"
    WITHOUT_BLOCKCHAIN = "without_blockchain"
    WITHOUT_RECOVERY_VERIFICATION = "without_recovery_verification"


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

    system: SystemName | AblationName
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


# Flat/default values the ablations below substitute for a genuinely computed
# one. MEDIUM is chosen for both (rather than LOW or HIGH) specifically so the
# ablation is a real "stop discriminating" change, not a disguised "assume
# everything is safe" or "assume everything is dangerous" -- either of which
# would bias the comparison instead of isolating the effect of removing the
# named component.
_FLAT_DEFAULT_CLINICAL_IMPACT = ImpactLevel.MEDIUM
_FLAT_DEFAULT_CRITICALITY = DeviceCriticality.MEDIUM

# Stub clinical context `detection_plus_risk_engine` feeds the real risk/policy
# engine when it skips the agent layer entirely -- fixed for every trial,
# deliberately uncorrelated with any trial's real `DeviceContext`, which is
# the whole point of the ablation (the risk/policy engine's rule tables are
# real, but they are reasoning about a context that was never actually
# looked up for this incident).
_STUB_CLINICAL_CONTEXT_KWARGS = {
    "device_criticality": _FLAT_DEFAULT_CRITICALITY,
    "patient_dependency": False,
    "clinical_impact_level": _FLAT_DEFAULT_CLINICAL_IMPACT,
}


def clinical_context_for(
    incident_id: str,
    device: DeviceContext,
    *,
    flat_clinical_impact: ImpactLevel | None = None,
    flat_criticality: DeviceCriticality | None = None,
) -> ClinicalContext:
    """Disclosed stand-in for the Healthcare Context Agent: `clinical_impact_level`
    has no ground-truth source of its own in this project (no real clinical
    simulation exists), so it is derived, honestly and simply, from the two
    fields that do have ground truth -- never an independent arbitrary value.
    Patient-dependent devices are always scored at least HIGH clinical impact;
    otherwise a HIGH-criticality device scores MEDIUM and anything else LOW.

    `flat_clinical_impact`/`flat_criticality` are `None` for every existing
    caller (`full_system`'s own behaviour is completely unchanged) and are
    only ever passed by `decide_full_system_variant`'s
    ``without_healthcare_context``/``without_clinical_criticality``
    ablations, to substitute a fixed value for the one this function would
    otherwise compute from `device` -- i.e. to genuinely turn the named
    computation off rather than merely relabel it."""
    criticality = flat_criticality if flat_criticality is not None else device.device_criticality

    if flat_clinical_impact is not None:
        impact = flat_clinical_impact
    elif device.patient_dependency:
        impact = ImpactLevel.HIGH
    elif device.device_criticality == DeviceCriticality.HIGH:
        impact = ImpactLevel.MEDIUM
    else:
        impact = ImpactLevel.LOW
    return ClinicalContext(
        incident_id=incident_id,
        device_criticality=criticality,
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


# Rule id reported by the experiment-only confidence gate below. It is NOT a rule of
# the real Policy Engine (`app/policy_engine/rules.py`); see the function's docstring.
CONFIDENCE_GATE_RULE_ID = "approval_low_detector_confidence"


def decide_full_system_confidence_gated(
    detection: DetectionOutcome,
    context: DeviceContext,
    incident_id: str,
    *,
    risk_model: RuleBasedRiskModel,
    policy_engine: PolicyEngine,
    min_autonomous_confidence: float,
) -> SystemDecision:
    """EXPERIMENT-ONLY variant: `full_system` plus one extra gate -- an action the
    real Policy Engine would execute autonomously is instead sent to human
    approval when the detector's own confidence is below
    `min_autonomous_confidence`.

    This exists to measure whether detector confidence separates real attacks
    from false alarms well enough to be worth adding to the Policy Engine; it
    deliberately does not touch `app/policy_engine/`. The gate can only turn an
    autonomous execution into an approval request, never the reverse, so it
    cannot make any decision less safe than `full_system`'s (asserted by tests
    and by the sweep).
    """
    base = decide_full_system(
        detection, context, incident_id, risk_model=risk_model, policy_engine=policy_engine
    )
    if base.executed_action is None or detection.confidence >= min_autonomous_confidence:
        return base
    return dataclasses.replace(
        base,
        requires_human_approval=True,
        executed_action=None,
        policy_rule_id=CONFIDENCE_GATE_RULE_ID,
    )


def decide_detection_plus_agentic_ai(
    detection: DetectionOutcome,
    context: DeviceContext,
    incident_id: str,
) -> SystemDecision:
    """Architecture's third named system: "detection + Agentic AI". Runs the
    same disclosed stand-ins for the Threat Reasoning and Healthcare Context
    Agents that `full_system` uses (`threat_assessment_for`,
    `clinical_context_for` -- see module docstring for what "agent" means
    here: no real LLM backend exists anywhere in this codebase, so these are
    deterministic, ground-truth-derived restatements, not invented
    reasoning), but then decides whether to execute from the agents' own
    output alone, through a small, explicitly-named heuristic -- it never
    calls `RuleBasedRiskModel`/`PolicyEngine` at all. That is exactly what
    distinguishes this system from `full_system`: agentic reasoning without
    the deterministic risk/policy backstop.

    Heuristic (disclosed, not a project-specified rule -- there is no
    Section-numbered spec for "Agentic AI acting alone" to implement
    literally): human approval is required whenever the Healthcare Context
    stand-in reports `patient_dependency=True` *and* the Threat Reasoning
    stand-in's `severity` is HIGH or CRITICAL, OR whenever
    `clinical_impact_level` itself is HIGH or CRITICAL -- the agents' own
    worst-case signal is enough to hold the action without a formal risk
    score; otherwise the proposed action executes autonomously. This is
    deliberately a simpler, less conservative gate than the Policy Engine's
    rule table (it has no check tied to the *specific* action category the
    way Section 13 rule 3 does), so a real difference from `full_system` is
    expected -- that gap is the point of comparing the two.
    """
    if not detection.fired:
        return SystemDecision(
            system=SystemName.DETECTION_PLUS_AGENTIC_AI,
            detection=detection,
            context=context,
            proposed_action=None,
            requires_human_approval=None,
            executed_action=None,
        )

    action = propose_action(detection)
    threat = threat_assessment_for(incident_id, detection)
    clinical_context = clinical_context_for(incident_id, context)

    high_severity = threat.severity in (ImpactLevel.HIGH, ImpactLevel.CRITICAL)
    high_impact = clinical_context.clinical_impact_level in (ImpactLevel.HIGH, ImpactLevel.CRITICAL)
    requires_human_approval = (clinical_context.patient_dependency and high_severity) or high_impact

    return SystemDecision(
        system=SystemName.DETECTION_PLUS_AGENTIC_AI,
        detection=detection,
        context=context,
        proposed_action=action,
        requires_human_approval=requires_human_approval,
        executed_action=None if requires_human_approval else action,
    )


def decide_detection_plus_risk_engine(
    detection: DetectionOutcome,
    context: DeviceContext,
    incident_id: str,
    *,
    risk_model: RuleBasedRiskModel,
    policy_engine: PolicyEngine,
) -> SystemDecision:
    """Architecture's fourth named system: "detection + deterministic risk
    engine". The inverse of `decide_detection_plus_agentic_ai` above: skips
    the agent layer entirely -- `clinical_context_for` (the Healthcare
    Context Agent stand-in) is never called for this trial's real `context`.
    A fixed stub `ClinicalContext` (`_STUB_CLINICAL_CONTEXT_KWARGS`) is used
    instead, deliberately uncorrelated with the trial's actual device
    criticality or patient dependency, and fed straight into the real
    `RuleBasedRiskModel`/`PolicyEngine` -- exactly as `full_system` does,
    just reasoning about a context nobody actually looked up for this
    incident.

    `threat_assessment_for` is still called: in this codebase it is not
    independent agent reasoning (see module docstring) but a direct,
    deterministic restatement of the detector's own predicted label and
    confidence into the `ThreatAssessment` schema the Risk Engine requires
    as input -- there is no agent step there left to skip.
    """
    if not detection.fired:
        return SystemDecision(
            system=SystemName.DETECTION_PLUS_RISK_ENGINE,
            detection=detection,
            context=context,
            proposed_action=None,
            requires_human_approval=None,
            executed_action=None,
        )

    action = propose_action(detection)
    threat = threat_assessment_for(incident_id, detection)
    stub_context = ClinicalContext(incident_id=incident_id, **_STUB_CLINICAL_CONTEXT_KWARGS)

    risk_score = risk_model.calculate_risk(
        threat,
        stub_context,
        [
            CandidateAction(
                action_category=action, description="Phase 13 evaluation candidate (stub context)"
            )
        ],
    )
    decision = policy_engine.evaluate_action(risk_score, stub_context, action)

    return SystemDecision(
        system=SystemName.DETECTION_PLUS_RISK_ENGINE,
        detection=detection,
        context=context,
        proposed_action=action,
        requires_human_approval=decision.requires_human_approval,
        executed_action=None if decision.requires_human_approval else action,
        policy_rule_id=decision.policy_rule_id,
    )


def decide_full_system_variant(
    detection: DetectionOutcome,
    context: DeviceContext,
    incident_id: str,
    *,
    risk_model: RuleBasedRiskModel,
    policy_engine: PolicyEngine,
    ablation: AblationName,
    flat_clinical_impact: ImpactLevel | None = None,
    flat_criticality: DeviceCriticality | None = None,
    disable_response_impact_assessment: bool = False,
) -> SystemDecision:
    """Generalized `full_system` decision path used by the three risk-formula
    ablations (`WITHOUT_HEALTHCARE_CONTEXT`, `WITHOUT_CLINICAL_CRITICALITY`,
    `WITHOUT_RESPONSE_IMPACT_ASSESSMENT`): identical to `decide_full_system`
    in every other respect (same `propose_action`, same real
    `RuleBasedRiskModel`/`PolicyEngine` call), with exactly one named
    computation genuinely disabled per call:

      - `flat_clinical_impact` forces every trial's `clinical_impact_level`
        to the same fixed value instead of letting `clinical_context_for`
        derive it from the device -- "no Healthcare Context Agent".
      - `flat_criticality` forces every trial's `device_criticality` (as fed
        to the risk/policy engine) to the same fixed value -- "no clinical
        criticality": `score_clinical_risk`'s criticality base and
        `score_response_impact`'s `high_criticality_dependent` check both
        stop discriminating by the device's real criticality.
      - `disable_response_impact_assessment` overwrites every entry of the
        *real* `RiskScore.response_impact` (computed first, by the real
        `score_response_impact` rule) to `ImpactLevel.LOW` immediately
        afterward -- i.e. the system behaves as if that term had never been
        assessed at all (it never escalates routing because of how
        disruptive the action is), while `cyber_risk`/`clinical_risk` are
        untouched. `risk_score.incident_id`/`cyber_risk`/`clinical_risk`/
        `explanation` all still come from the real scoring call; only the
        one named field is overwritten after the fact.

    `decision.context` below is always the trial's *real* `DeviceContext`
    (never the flattened one fed to the engine) -- the unsafe/unnecessary
    metrics in `run_baseline_comparison.py` must judge every system against
    the same ground truth, or a system that is blind to real risk could
    never be shown to actually be more unsafe.
    """
    if not detection.fired:
        return SystemDecision(
            system=ablation,
            detection=detection,
            context=context,
            proposed_action=None,
            requires_human_approval=None,
            executed_action=None,
        )

    action = propose_action(detection)
    threat = threat_assessment_for(incident_id, detection)
    clinical_context = clinical_context_for(
        incident_id,
        context,
        flat_clinical_impact=flat_clinical_impact,
        flat_criticality=flat_criticality,
    )

    risk_score = risk_model.calculate_risk(
        threat,
        clinical_context,
        [
            CandidateAction(
                action_category=action, description=f"Phase 13 ablation candidate ({ablation.value})"
            )
        ],
    )

    if disable_response_impact_assessment:
        risk_score = risk_score.model_copy(
            update={"response_impact": {k: ImpactLevel.LOW for k in risk_score.response_impact}}
        )

    decision = policy_engine.evaluate_action(risk_score, clinical_context, action)

    return SystemDecision(
        system=ablation,
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


# ---------------------------------------------------------------------------
# WITHOUT_BLOCKCHAIN and WITHOUT_RECOVERY_VERIFICATION
#
# Neither ablation changes a single line of the decision path above. Stated
# plainly rather than silently glossed over:
#
# WITHOUT_BLOCKCHAIN: nothing in `baseline_systems.py` or
# `run_baseline_comparison.py` ever calls `app/blockchain/` (no
# `OutboxWorker`, no `MockFabricClient`/`FabricClient`, no provenance write)
# for *any* system, including `full_system` -- provenance recording is an
# audit/evidence concern (Section 14) that happens alongside an incident's
# lifecycle in the real API path (`backend/tests/test_blockchain_integration.py`
# exercises that), not a step this batch decision-logic harness was ever
# wired through. So "with blockchain" and "without blockchain" are, in this
# harness, the exact same code path -- `run_baseline_comparison.py` reuses
# `decide_full_system`'s own decisions for the `WITHOUT_BLOCKCHAIN` ablation
# rather than introducing a second, duplicate call that could only ever
# produce identical numbers. This is reported as a confirmed, honest "no
# effect by construction" finding, not measured as if it were an open
# question.
#
# WITHOUT_RECOVERY_VERIFICATION: Recovery verification (Section 7 step 12,
# `app/agents/recovery_verification.py` + `app/recovery/engine.py`) is a
# *post-execution* check -- it re-examines device/network state after a
# response has already run, which this harness's per-row trials have no
# model of (each trial is one independent classifier row, not a
# before/after device-state simulation; see `datasets/LICENSE_NOTES.md` /
# `synthetic_data.py`). So this ablation cannot change
# `unsafe_autonomous_action_rate` or `unnecessary_isolation_rate` either --
# both are measured at the decision step, before any recovery check would
# run. What it *can* measure honestly: for every trial where `full_system`
# executed an action autonomously, would a real Recovery Verification Agent
# call have flagged it for reinvestigation rather than letting it close as
# resolved? `recovery_result_would_require_reinvestigation` below is a
# disclosed, deterministic stand-in for that agent (same category of
# simplification as `threat_assessment_for`/`clinical_context_for` above,
# extended to this one remaining agent) -- "without recovery verification"
# means every one of those executed trials is instead marked resolved
# unconditionally (`run_baseline_comparison.py`'s literal behaviour, since it
# never calls this function for that ablation), silently losing exactly the
# trials this function flags.
def recovery_result_would_require_reinvestigation(
    detection: DetectionOutcome, context: DeviceContext, decision: SystemDecision
) -> bool:
    """Disclosed stand-in for the Recovery Verification Agent
    (`app/agents/recovery_verification.py`): no real LLM backend and no live
    device/network state exists in this synthetic, single-shot trial harness
    to genuinely re-check (module docstring) -- so, honestly, the one thing
    that *is* ground truth here is reused: whether the action actually
    executed was the more severe of the two this experiment ever proposes.

    Returns `True` (containment not verified, would reinvestigate) only when
    all of: an action executed autonomously this trial, the row's real label
    was actually an attack (nothing to verify on a false positive -- the
    device was never compromised, so "recovery" is vacuously fine), the
    device context is high-stakes, *and* the action taken was the MODERATE
    action (`isolate_non_critical`), not the SEVERE one (`shutdown`) --
    i.e. the one case among this experiment's two fixed candidate actions
    where a less-disruptive response was chosen on a high-stakes real
    attack, the plausible case for containment having been insufficient.
    Never claims to detect an actual containment failure that isn't
    reducible to that one ground-truth fact.
    """
    if decision.executed_action is None:
        return False
    if not detection.ground_truth_is_attack:
        return False
    return is_high_stakes(context) and decision.executed_action == _MODERATE_ACTION
