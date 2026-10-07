"""L9 — Blockchain provenance schemas.

Architecture spec Section 14: these mirror the six chaincode operations exactly.
Only hashes and structured metadata — never raw telemetry, logs, or patient
identifiers cross into these models.
"""

from datetime import datetime

from pydantic import BaseModel

from app.schemas.enums import ApprovalDecision, ResponseActionCategory


class IncidentProvenance(BaseModel):
    incident_id: str
    device_id: str
    attack_type: str
    evidence_hash: str
    timestamp: datetime


class DecisionProvenance(BaseModel):
    incident_id: str
    risk_score_hash: str
    policy_rule_id: str
    recommended_action: ResponseActionCategory


class ApprovalProvenance(BaseModel):
    incident_id: str
    approver_identity: str
    decision: ApprovalDecision
    timestamp: datetime


class ResponseProvenance(BaseModel):
    incident_id: str
    action_taken: ResponseActionCategory
    executed_by: str
    timestamp: datetime


class RecoveryProvenance(BaseModel):
    incident_id: str
    recovery_verified: bool
    residual_threats_hash: str | None = None
