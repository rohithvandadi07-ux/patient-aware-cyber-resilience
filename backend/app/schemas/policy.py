"""L6 — Safety / Policy Engine schema.

Architecture spec Section 13: every policy decision is logged with the specific
rule that fired, not just the outcome — required for both the dashboard's
explanation and the "unsafe response rate" evaluation metric to mean anything.
"""

from pydantic import BaseModel, Field

from app.schemas.enums import ResponseActionCategory


class PolicyDecision(BaseModel):
    incident_id: str
    chosen_action: ResponseActionCategory
    requires_human_approval: bool
    policy_rule_id: str = Field(description="Identifier of the specific rule that produced this decision.")
    rationale: str
