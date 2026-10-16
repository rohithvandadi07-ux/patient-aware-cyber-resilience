"""PolicyEngine -- wires `rules.py`'s rule table into `PolicyDecision` objects.

Architecture spec Section 13 names the Policy Engine's input as a `RiskScore`
plus the chosen response action, and its output as a `PolicyDecision` with a
`policy_rule_id` naming exactly which rule fired. This module is deliberately
thin, same as `risk_engine/rule_based.py`'s relationship to `risk_engine/rules.py`:
no rule logic lives here, only wiring and the incident-id/scoring-consistency
checks that make it safe to trust the result.

Two entry points, for two different callers:
  - `evaluate_action`: single pre-chosen action -> one `PolicyDecision`. This is
    what the Response Planning Agent's `AgentToolkit.evaluate_policy` tool call
    needs (task 45) when it is probing "would this specific candidate be
    auto-approved" before committing to a recommendation.
  - `evaluate`: Section 13's literal input shape -- a `RiskScore` plus a full
    `ProposedResponse` -- routes on `proposed_response.recommended_action`,
    the one action the agent actually recommends. This is what the Response
    Orchestrator (Phase 6/7) calls once a recommendation has been finalized.
Both ultimately call `evaluate_action`; `evaluate` is a thin extraction of the
one field it needs from `ProposedResponse`.
"""

from app.policy_engine.rules import (
    _IMPACT_ORDER,
    apply_confidence_gate,
    decide_routing,
    get_response_impact_for_action,
)
from app.schemas.agents import ClinicalContext, ProposedResponse
from app.schemas.enums import ResponseActionCategory
from app.schemas.policy import AlternativeAction, PolicyDecision
from app.schemas.risk import RiskScore


class PolicyEngine:
    """L6 Policy Engine: no LLM call anywhere in this class or anything it calls.

    Every method here either returns a `PolicyDecision` built from a named
    rule in `rules.py`, or raises -- it never silently defaults a routing
    decision, because this is "the layer agents must never be able to bypass"
    (Section 13), not a layer entitled to guess.

    `min_autonomous_confidence` (default None = off) enables the optional
    confidence gate in `rules.apply_confidence_gate`: an otherwise-autonomous
    action goes to human approval when the detector's confidence is below
    this value, or unknown. Off, the engine is exactly Section 13's rules.
    """

    def __init__(self, min_autonomous_confidence: float | None = None) -> None:
        if min_autonomous_confidence is not None and not 0.0 < min_autonomous_confidence <= 1.0:
            raise ValueError("min_autonomous_confidence must be in (0, 1] or None")
        self._min_autonomous_confidence = min_autonomous_confidence

    @property
    def min_autonomous_confidence(self) -> float | None:
        return self._min_autonomous_confidence

    def evaluate_action(
        self,
        risk_score: RiskScore,
        context: ClinicalContext,
        action_category: ResponseActionCategory,
        detection_confidence: float | None = None,
    ) -> PolicyDecision:
        """Route one specific, already-chosen action.

        Raises `ValueError` if `risk_score.incident_id` and
        `context.incident_id` disagree (refusing to assemble a decision that
        mixes evidence from two different incidents, mirroring
        `RuleBasedRiskModel`'s own incident-id check), or if `action_category`
        was never scored in `risk_score.response_impact` (surfaced by
        `rules.get_response_impact_for_action`, not swallowed here).
        """
        if risk_score.incident_id != context.incident_id:
            raise ValueError(
                f"risk_score.incident_id ({risk_score.incident_id!r}) and context.incident_id "
                f"({context.incident_id!r}) must match -- refusing to assemble a PolicyDecision "
                "that mixes evidence from two different incidents"
            )

        requires_human_approval, policy_rule_id, rationale = apply_confidence_gate(
            decide_routing(risk_score, context, action_category),
            detection_confidence,
            self._min_autonomous_confidence,
        )

        return PolicyDecision(
            incident_id=risk_score.incident_id,
            chosen_action=action_category,
            requires_human_approval=requires_human_approval,
            policy_rule_id=policy_rule_id,
            rationale=rationale,
        )

    def evaluate(
        self,
        risk_score: RiskScore,
        proposed_response: ProposedResponse,
        context: ClinicalContext,
        detection_confidence: float | None = None,
    ) -> PolicyDecision:
        """Section 13's literal input shape: a `RiskScore` plus a full
        `ProposedResponse`, routed on `proposed_response.recommended_action`
        -- the one action the Response Planning Agent actually recommends,
        not every candidate it considered.

        Raises `ValueError` if `proposed_response.incident_id` disagrees with
        either `risk_score.incident_id` or `context.incident_id`, for the same
        reason `evaluate_action` checks the other two against each other.
        """
        if proposed_response.incident_id != risk_score.incident_id:
            raise ValueError(
                f"proposed_response.incident_id ({proposed_response.incident_id!r}) and "
                f"risk_score.incident_id ({risk_score.incident_id!r}) must match -- refusing to "
                "assemble a PolicyDecision that mixes evidence from two different incidents"
            )

        decision = self.evaluate_action(
            risk_score, context, proposed_response.recommended_action, detection_confidence
        )
        decision.alternatives = self._rank_alternatives(
            risk_score, proposed_response, context, detection_confidence
        )
        return decision

    def _rank_alternatives(
        self,
        risk_score: RiskScore,
        proposed_response: ProposedResponse,
        context: ClinicalContext,
        detection_confidence: float | None,
    ) -> list[AlternativeAction]:
        """The non-chosen, scored candidates, routed exactly like the chosen
        action (same rules, same confidence gate). A candidate the Risk Engine
        never scored is skipped rather than guessed at."""
        alternatives: list[AlternativeAction] = []
        seen = {proposed_response.recommended_action}
        for candidate in proposed_response.candidate_actions:
            action = candidate.action_category
            if action in seen:
                continue
            seen.add(action)
            try:
                impact = get_response_impact_for_action(risk_score, action)
            except ValueError:
                continue
            requires_approval, rule_id, _ = apply_confidence_gate(
                decide_routing(risk_score, context, action),
                detection_confidence,
                self._min_autonomous_confidence,
            )
            alternatives.append(
                AlternativeAction(
                    action=action,
                    response_impact=impact,
                    requires_human_approval=requires_approval,
                    policy_rule_id=rule_id,
                    security_benefit=proposed_response.security_benefit.get(action.value),
                )
            )
        alternatives.sort(
            key=lambda a: (
                a.requires_human_approval,
                _IMPACT_ORDER[a.response_impact],
                -(a.security_benefit if a.security_benefit is not None else -1.0),
            )
        )
        return alternatives
