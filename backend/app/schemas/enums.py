"""Shared enumerations used across schemas.

Centralized here so every layer (detection, agents, risk engine, policy engine)
refers to the same vocabulary instead of each defining its own string literals.
"""

from enum import StrEnum


class DeviceCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ImpactLevel(StrEnum):
    """Used for both clinical impact and response impact — same scale, so a
    RiskScore's per-action response_impact is directly comparable to a
    ClinicalContext's clinical_impact_level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(StrEnum):
    """Scope matches architecture spec Section 10 — narrowed to what the selected
    datasets (CICIoMT2024, WUSTL-EHMS-2020) actually label with adequate samples.
    Not the full brief candidate list; extend only when a specific dataset or
    scenario justifies it."""

    DOS = "dos"
    DDOS = "ddos"
    RECONNAISSANCE = "reconnaissance"
    MQTT_BASED = "mqtt_based"
    SPOOFING = "spoofing"
    MITM_INJECTION = "mitm_injection"
    UNKNOWN = "unknown"


class ResponseActionCategory(StrEnum):
    """Matches the Policy Engine's rule table categories (architecture spec
    Section 13) — the category, not the specific action, is what policy rules key
    off of."""

    BLOCK_TRAFFIC = "block_traffic"
    REVOKE_SESSION = "revoke_session"
    ROTATE_CREDENTIALS = "rotate_credentials"
    RESTRICT_COMMUNICATION = "restrict_communication"
    ISOLATE_NON_CRITICAL = "isolate_non_critical"
    ISOLATE_CRITICAL = "isolate_critical"
    QUARANTINE_SEGMENT = "quarantine_segment"
    ACTIVATE_BACKUP = "activate_backup"
    RESTART_SERVICE = "restart_service"
    FAILOVER = "failover"
    SHUTDOWN = "shutdown"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class IncidentStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    RISK_ASSESSED = "risk_assessed"
    AWAITING_APPROVAL = "awaiting_approval"
    RESPONSE_EXECUTING = "response_executing"
    RECOVERY_VERIFYING = "recovery_verifying"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    INVESTIGATION_STALLED = "investigation_stalled"
    # Per-stage stall statuses (architecture spec Section 11: "marks the
    # incident `investigation_stalled` (or the equivalent per stage)").
    # INVESTIGATION_STALLED above predates Phase 4 and covers the
    # Investigation Agent specifically; these four cover the other four
    # agents so a dashboard/test can tell *which* stage actually stalled
    # instead of collapsing every agent failure into one status.
    THREAT_REASONING_STALLED = "threat_reasoning_stalled"
    CONTEXT_STALLED = "context_stalled"
    RESPONSE_PLANNING_STALLED = "response_planning_stalled"
    RECOVERY_VERIFICATION_STALLED = "recovery_verification_stalled"


class OutboxRecordType(StrEnum):
    """Which of the five chaincode *write* operations (architecture spec
    Section 14) an outbox entry's payload is bound for. `verifyEvidence` is
    a read-only query, not a write, so it has no outbox entry type --
    nothing is ever queued to verify evidence; that's called directly."""

    INCIDENT = "incident"
    DECISION = "decision"
    APPROVAL = "approval"
    RESPONSE = "response"
    RECOVERY = "recovery"


class OutboxStatus(StrEnum):
    """Architecture spec Section 14: an off-chain record's `chain_tx_id`
    is nullable, and `IS NULL` means "not yet committed" -- a real,
    visible state, never silently hidden. PENDING is that nullable state;
    CONFIRMED is once `chain_tx_id` is populated; FAILED is a
    non-retryable chaincode rejection (bad input, or a business rule like
    "incident already recorded") rather than a transient endorsement
    timing issue, which the outbox worker retries instead of failing."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
