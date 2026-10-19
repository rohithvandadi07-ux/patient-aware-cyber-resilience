"""Read-only view of the active routing policy and its hash."""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.policy_engine.table import get_active_table

# Load at import so an invalid POLICY_FILE stops the app from starting (fail closed).
get_active_table()

router = APIRouter(prefix="/policy", tags=["policy"])


class PolicyRuleView(BaseModel):
    id: str
    when: dict[str, Any]
    requires_human_approval: bool
    rationale: str


class PolicyView(BaseModel):
    name: str
    version: int
    policy_hash: str
    source: str
    safety_floor: list[str]
    rules: list[PolicyRuleView]


@router.get("", response_model=PolicyView)
def get_policy() -> PolicyView:
    return PolicyView(**get_active_table().describe())
