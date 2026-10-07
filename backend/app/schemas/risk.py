"""L5 — Patient-Aware Dual-Risk Engine schema.

Architecture spec Section 12: the interface is fixed now, the function behind it is
not. `response_impact` carries one estimate per candidate action (not a single
aggregate), because different response actions have different clinical impact on
the same device, and the Policy Engine needs to compare them.
"""

from pydantic import BaseModel, Field

from app.schemas.enums import ImpactLevel


class RiskScore(BaseModel):
    incident_id: str
    cyber_risk: float = Field(ge=0.0, le=1.0)
    clinical_risk: float = Field(ge=0.0, le=1.0)
    response_impact: dict[str, ImpactLevel] = Field(
        description="Per-action-category clinical/operational impact estimate, keyed by "
        "ResponseActionCategory value. One entry per candidate action under consideration."
    )
    explanation: str = Field(
        description="Human-readable rationale for the scores above — required for the SOC "
        "dashboard's explanation field and for auditability of the risk model's output."
    )
