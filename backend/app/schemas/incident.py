"""The Incident aggregate.

Architecture spec Section 7: an Incident always carries a reference to a simulated
device's live context — never a dataset row's metadata, which has none of that.
This is the object every agent, the risk engine, the policy engine, and the
blockchain outbox all key off of.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import IncidentStatus


class Incident(BaseModel):
    incident_id: str
    device_id: str
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    chain_tx_id: str | None = Field(
        default=None,
        description="Set once blockchain provenance for this incident's creation is confirmed.",
    )
