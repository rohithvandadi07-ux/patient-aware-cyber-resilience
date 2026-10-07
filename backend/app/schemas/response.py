"""L7/L8 — Response execution and approval schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import ApprovalDecision, ResponseActionCategory


class ApprovalRecord(BaseModel):
    incident_id: str
    approver_identity: str
    decision: ApprovalDecision
    timestamp: datetime
    notes: str | None = None


class ExecutedResponse(BaseModel):
    incident_id: str
    action_taken: ResponseActionCategory
    executed_by: str = Field(
        description="'system' for autonomous execution, or a user identity after approval."
    )
    timestamp: datetime
    chain_tx_id: str | None = Field(
        default=None,
        description="Hyperledger Fabric transaction ID once the async outbox worker confirms "
        "provenance was recorded. Null means not yet committed — never hidden as if absent.",
    )
