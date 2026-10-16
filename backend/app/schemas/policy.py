"""L6 — Safety / Policy Engine schema.

Architecture spec Section 13: every policy decision is logged with the specific
rule that fired, not just the outcome — required for both the dashboard's
explanation and the "unsafe response rate" evaluation metric to mean anything.
"""

from pydantic import BaseModel, Field

from app.schemas.enums import ImpactLevel, ResponseActionCategory


class AlternativeAction(BaseModel):
    """A candidate action the Response Planning Agent considered but the Policy
    Engine's decision did not choose, routed by the same rules as the chosen one,
    so an operator can see what the safer or faster alternatives would have
    required (autonomous vs. approval) and at what clinical response impact."""

    action: ResponseActionCategory
    response_impact: ImpactLevel
    requires_human_approval: bool
    policy_rule_id: str
    security_benefit: float | None = Field(
        default=None, description="The agent's stated security benefit for this action, if it gave one."
    )


class PolicyDecision(BaseModel):
    incident_id: str
    chosen_action: ResponseActionCategory
    requires_human_approval: bool
    policy_rule_id: str = Field(description="Identifier of the specific rule that produced this decision.")
    rationale: str
    alternatives: list[AlternativeAction] = Field(
        default_factory=list,
        description="Other candidate actions, routed by the same rules and ranked: autonomous before "
        "approval-required, then lower response impact, then higher security benefit. Empty when the "
        "decision came from `evaluate_action` (a single pre-chosen action) or the proposal had no "
        "other scored candidates.",
    )
