"""L3 — Cybersecurity Detection Engine output contract.

Architecture spec Section 10: the detection engine never emits a bare label. This
is the one piece of structured evidence the Investigation Agent (L4) is allowed to
treat as ground truth.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import AttackCategory, ImpactLevel


class DetectionEvent(BaseModel):
    """A single detection emitted by the detection engine against a live event
    stream. Creates or updates an Incident; never fabricated — only produced by a
    trained model scoring real feature vectors."""

    device_id: str
    attack_type: AttackCategory
    confidence: float = Field(ge=0.0, le=1.0)
    severity_hint: ImpactLevel
    timestamp: datetime
    evidence_ref: str = Field(
        description="Reference to the underlying evidence (log range, flow records, "
        "or event IDs) backing this detection — never the raw evidence itself."
    )
