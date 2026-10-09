"""Structured output schemas for each agent role.

Every agent's output is validated against a Pydantic model before it is
accepted. An agent that returns malformed output is retried; one that fails
validation repeatedly is recorded as VALIDATION_FAILED and its output is
discarded rather than passed downstream.

This matters because the specification requires that agent outputs be
validated and that agents not be permitted to "invent evidence". Validation
catches the structural half of that: a finding must cite its epistemic
status, confidences must be in range, and an action must be a real member
of the response enum rather than free text.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.domain.enums import (
    AgentRole,
    AssertionClass,
    AttackType,
    CriticalityTier,
    PatientDependencyLevel,
    RecoveryOutcome,
    ResponseActionType,
    Severity,
)


class AgentOutput(BaseModel):
    """Base for all agent outputs."""

    model_config = ConfigDict(extra="ignore")

    findings: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("findings")
    @classmethod
    def _validate_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        valid = {a.value for a in AssertionClass}
        out = []
        for f in v:
            if "statement" not in f:
                raise ValueError("every finding must have a 'statement'")
            cls_name = f.get("assertion_class")
            if cls_name not in valid:
                raise ValueError(
                    f"finding assertion_class must be one of {sorted(valid)}, "
                    f"got {cls_name!r}. Observed fact, inference and "
                    "recommendation must be distinguished."
                )
            confidence = float(f.get("confidence", 0.5))
            if not 0.0 <= confidence <= 1.0:
                raise ValueError(f"finding confidence {confidence} outside [0,1]")
            out.append({**f, "confidence": confidence})
        return out


class InvestigationOutput(AgentOutput):
    affected_assets: list[str] = Field(default_factory=list)
    evidence_reviewed: int = 0
    evidence_verified: int = 0
    telemetry_samples: int = 0
    network_records: int = 0
    security_events: int = 0
    source_identities: list[str] = Field(default_factory=list)
    timeline_reconstructed: bool = False

    @field_validator("evidence_verified")
    @classmethod
    def _verified_not_more_than_reviewed(cls, v: int, info) -> int:
        reviewed = info.data.get("evidence_reviewed", 0)
        if v > reviewed:
            raise ValueError(
                f"evidence_verified ({v}) exceeds evidence_reviewed ({reviewed}); "
                "an agent cannot verify evidence it did not review"
            )
        return v


class ThreatReasoningOutput(AgentOutput):
    attack_type: AttackType = AttackType.UNKNOWN
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    cyber_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    propagation_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    persistence: float | None = Field(default=None, ge=0.0, le=1.0)


class HealthcareContextOutput(AgentOutput):
    device_criticality: CriticalityTier | None = None
    patient_dependency: PatientDependencyLevel | None = None
    life_support_involved: bool = False
    clinical_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    safety_constraints: list[str] = Field(default_factory=list)


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action_type: ResponseActionType
    security_benefit: float | None = Field(default=None, ge=0.0, le=1.0)
    clinical_impact: float | None = Field(default=None, ge=0.0, le=1.0)
    impact_class: str | None = None
    rationale: str = ""


class ResponsePlanningOutput(AgentOutput):
    candidate_actions: list[CandidateAction] = Field(default_factory=list)
    rejected_actions: list[dict[str, Any]] = Field(default_factory=list)
    recommended_action: ResponseActionType = ResponseActionType.ESCALATE_TO_CLINICAL_STAFF
    requires_human_approval: bool = True
    cyber_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    clinical_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("candidate_actions")
    @classmethod
    def _no_unsafe_candidates(cls, v: list[CandidateAction]) -> list[CandidateAction]:
        unsafe = [c.action_type.value for c in v if c.impact_class == "unsafe"]
        if unsafe:
            raise ValueError(
                f"candidate list contains actions classified UNSAFE: {unsafe}. "
                "An agent must not propose an action the risk engine has "
                "classified unsafe."
            )
        return v


class RecoveryVerificationOutput(AgentOutput):
    outcome: RecoveryOutcome = RecoveryOutcome.FAILED
    residual_risk: float = Field(default=1.0, ge=0.0, le=1.0)
    requires_reinvestigation: bool = True
    residual_cyber_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    failed_checks: list[str] = Field(default_factory=list)


OUTPUT_SCHEMAS: dict[AgentRole, type[AgentOutput]] = {
    AgentRole.INVESTIGATION: InvestigationOutput,
    AgentRole.THREAT_REASONING: ThreatReasoningOutput,
    AgentRole.HEALTHCARE_CONTEXT: HealthcareContextOutput,
    AgentRole.RESPONSE_PLANNING: ResponsePlanningOutput,
    AgentRole.RECOVERY_VERIFICATION: RecoveryVerificationOutput,
}


def schema_for(role: AgentRole) -> type[AgentOutput]:
    return OUTPUT_SCHEMAS[role]


def json_schema_for(role: AgentRole) -> dict[str, Any]:
    return OUTPUT_SCHEMAS[role].model_json_schema()


__all__ = [
    "OUTPUT_SCHEMAS",
    "AgentOutput",
    "CandidateAction",
    "HealthcareContextOutput",
    "InvestigationOutput",
    "RecoveryVerificationOutput",
    "ResponsePlanningOutput",
    "ThreatReasoningOutput",
    "json_schema_for",
    "schema_for",
]
