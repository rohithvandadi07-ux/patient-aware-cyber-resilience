"""L4 — Agentic Investigation + Reasoning schemas.

Architecture spec Section 11: each agent has a fixed input/output schema and no
agent holds an execute capability. A field's name encodes its epistemic status per
the brief's Section 26 (observed fact vs. inference vs. recommendation) —
`evidence`/`observations` are what was found, `reasoning_summary`/`rationale` is
interpretation, `recommended_action` is a recommendation, never an instruction to
act.
"""

from pydantic import BaseModel, Field

from app.schemas.enums import AttackCategory, DeviceCriticality, ImpactLevel, ResponseActionCategory


class InvestigationReport(BaseModel):
    """Output of the Investigation Agent."""

    incident_id: str
    evidence: list[str] = Field(description="Observed facts only — log lines, event IDs, raw findings.")
    timeline: list[str] = Field(description="Ordered, timestamped reconstruction of what happened.")
    affected_devices: list[str]
    observations: list[str] = Field(description="Investigator's observations, distinct from raw evidence.")
    confidence: float = Field(ge=0.0, le=1.0)


class ThreatAssessment(BaseModel):
    """Output of the Threat Reasoning Agent."""

    incident_id: str
    attack_type: AttackCategory
    severity: ImpactLevel
    confidence: float = Field(ge=0.0, le=1.0)
    propagation_risk: ImpactLevel
    reasoning_summary: str = Field(description="Interpretation, not observed fact.")


class ClinicalContext(BaseModel):
    """Output of the Healthcare Context Agent."""

    incident_id: str
    device_criticality: DeviceCriticality
    patient_dependency: bool
    clinical_impact_level: ImpactLevel = Field(
        description="Estimated clinical impact if the affected device were disrupted."
    )
    safety_constraints: list[str] = Field(
        default_factory=list,
        description="Explicit constraints the Policy Engine must respect for this device "
        "(e.g. 'ventilator must not be powered off while patient_dependency is true').",
    )


class CandidateAction(BaseModel):
    action_category: ResponseActionCategory
    description: str


class ProposedResponse(BaseModel):
    """Output of the Response Planning Agent.

    This schema has no execute method and no field that triggers execution — it is
    a proposal only. Only the Policy Engine (L6) and, downstream of it, the
    Response Orchestrator (L7) can turn this into an executed action.
    """

    incident_id: str
    candidate_actions: list[CandidateAction]
    security_benefit: dict[str, float] = Field(
        description="Per-action-category estimated cyber-security benefit, keyed by action_category value."
    )
    clinical_impact: dict[str, ImpactLevel] = Field(
        description="Per-action-category estimated clinical impact, keyed by action_category value."
    )
    recommended_action: ResponseActionCategory
    rationale: str = Field(
        description="Recommendation, not an instruction — the Policy Engine decides routing."
    )


class RecoveryResult(BaseModel):
    """Output of the Recovery Verification Agent."""

    incident_id: str
    response_id: str
    containment_verified: bool
    residual_threats: list[str] = Field(default_factory=list)
    recovery_succeeded: bool
    reinvestigation_required: bool
