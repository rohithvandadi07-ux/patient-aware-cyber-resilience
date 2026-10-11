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

from app.policy_engine.rules import decide_routing
from app.schemas.agents import ClinicalContext, ProposedResponse
from app.schemas.enums import ResponseActionCategory
from app.schemas.policy import PolicyDecision
from app.schemas.risk import RiskScore


class PolicyEngine:
    """L6 Policy Engine: no LLM call anywhere in this class or anything it calls.

    Every method here either returns a `PolicyDecision` built from a named
    rule in `rules.py`, or raises -- it never silently defaults a routing
    decision, because this is "the layer agents must never be able to bypass"
    (Section 13), not a layer entitled to guess.
    """

    def evaluate_action(
        self,
        risk_score: RiskScore,
        context: ClinicalContext,
        action_category: ResponseActionCategory,
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

        requires_human_approval, policy_rule_id, rationale = decide_routing(
            risk_score, context, action_category
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

        return self.evaluate_action(risk_score, context, proposed_response.recommended_action)
