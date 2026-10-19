"""Read-only view of the active routing policy, its hash, and whether it is anchored on the ledger."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.dependencies import get_outbox_repository
from app.blockchain.outbox import OutboxRepository
from app.blockchain.policy_anchor import policy_anchor_status
from app.policy_engine.table import get_active_table

# Load at import so an invalid POLICY_FILE stops the app from starting (fail closed).
get_active_table()

router = APIRouter(prefix="/policy", tags=["policy"])


class PolicyRuleView(BaseModel):
    id: str
    when: dict[str, Any]
    requires_human_approval: bool
    rationale: str


class PolicyAnchor(BaseModel):
    state: str
    chain_tx_id: str | None = None
    last_error: str | None = None


class PolicyView(BaseModel):
    name: str
    version: int
    policy_hash: str
    source: str
    safety_floor: list[str]
    rules: list[PolicyRuleView]
    anchor: PolicyAnchor


@router.get("", response_model=PolicyView)
def get_policy(repo: OutboxRepository = Depends(get_outbox_repository)) -> PolicyView:
    table = get_active_table()
    anchor = PolicyAnchor(**policy_anchor_status(repo, table.policy_hash))
    return PolicyView(**table.describe(), anchor=anchor)
