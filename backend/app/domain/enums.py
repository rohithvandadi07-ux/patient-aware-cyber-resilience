"""Canonical enumerations shared across every subsystem.

These are the vocabulary of the platform. Detection, incident intelligence,
the agentic layer, the risk engine, the policy engine, the response
orchestrator, recovery verification and the provenance ledger all speak in
these terms, which is what keeps the platform one coherent system rather
than a set of adjacent demos.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):  # noqa: UP042
    """String-valued enum that serialises to its value.

    Deliberately ``str, Enum`` rather than :class:`enum.StrEnum` so that
    Pydantic v2 serialises members to their value identically on 3.11 and
    3.12+, which keeps provenance payload hashes stable across versions.
    """

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


# ---------------------------------------------------------------------------
# Devices and clinical context
# ---------------------------------------------------------------------------
class DeviceType(StrEnum):
    INFUSION_PUMP = "infusion_pump"
    VENTILATOR = "ventilator"
    ECG_MONITOR = "ecg_monitor"
    WEARABLE_SENSOR = "wearable_sensor"
    # Non-clinical assets present so the policy engine has genuinely
    # low-criticality targets to act on autonomously.
    WORKSTATION = "workstation"
    NETWORK_GATEWAY = "network_gateway"


class DeviceOperationalState(StrEnum):
    """Operational state of the simulated device itself."""

    OFFLINE = "offline"
    STANDBY = "standby"
    ACTIVE = "active"
    ALARM = "alarm"
    DEGRADED = "degraded"
    FAULT = "fault"
    MAINTENANCE = "maintenance"
    QUARANTINED = "quarantined"
    ISOLATED = "isolated"


class NetworkState(StrEnum):
    NORMAL = "normal"
    RESTRICTED = "restricted"
    SEGMENTED = "segmented"
    ISOLATED = "isolated"
    UNREACHABLE = "unreachable"


class CriticalityTier(StrEnum):
    """Clinical criticality of a device class.

    LIFE_SUSTAINING  - interruption may be immediately life-threatening
    LIFE_SUPPORTING  - interruption causes rapid clinical deterioration
    CLINICALLY_SIGNIFICANT - interruption degrades care but is tolerable
    SUPPORTIVE       - informational / convenience
    NON_CLINICAL     - no direct patient-care role
    """

    LIFE_SUSTAINING = "life_sustaining"
    LIFE_SUPPORTING = "life_supporting"
    CLINICALLY_SIGNIFICANT = "clinically_significant"
    SUPPORTIVE = "supportive"
    NON_CLINICAL = "non_clinical"


class PatientDependencyLevel(StrEnum):
    """How dependent the attached synthetic patient is on this device."""

    NONE = "none"
    INTERMITTENT = "intermittent"
    CONTINUOUS = "continuous"
    LIFE_CRITICAL = "life_critical"


class AcuityLevel(StrEnum):
    """Synthetic patient acuity, used only as clinical-risk context."""

    NONE = "none"
    STABLE = "stable"
    GUARDED = "guarded"
    SERIOUS = "serious"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Threats and detection
# ---------------------------------------------------------------------------
class AttackType(StrEnum):
    """Threat classes inside the defensible threat model.

    Scoped deliberately: every member here is observable in the simulator's
    telemetry/network/auth event streams AND is represented in at least one
    of the surveyed public IoMT security datasets. See docs/threat-model.md.
    """

    NONE = "none"
    DOS = "dos"
    DDOS = "ddos"
    RECONNAISSANCE = "reconnaissance"
    PORT_SCAN = "port_scan"
    ARP_SPOOFING = "arp_spoofing"
    MITM = "mitm"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CREDENTIAL_BRUTE_FORCE = "credential_brute_force"
    SPOOFED_TELEMETRY = "spoofed_telemetry"
    MALICIOUS_COMMAND = "malicious_command"
    FIRMWARE_TAMPER = "firmware_tamper"
    RANSOMWARE_BEHAVIOUR = "ransomware_behaviour"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventKind(StrEnum):
    """Normalised event taxonomy emitted by the event/telemetry layer."""

    TELEMETRY = "telemetry"
    NETWORK_FLOW = "network_flow"
    DEVICE_STATE = "device_state"
    DEVICE_COMMAND = "device_command"
    AUTH = "auth"
    SECURITY_LOG = "security_log"
    SYSTEM = "system"


class DetectorKind(StrEnum):
    SUPERVISED_CLASSIFIER = "supervised_classifier"
    ANOMALY_DETECTOR = "anomaly_detector"
    RULE_ENGINE = "rule_engine"
    ENSEMBLE = "ensemble"


# ---------------------------------------------------------------------------
# Incident lifecycle
# ---------------------------------------------------------------------------
class IncidentState(StrEnum):
    """Incident lifecycle states mandated by the specification."""

    DETECTED = "detected"
    INVESTIGATING = "investigating"
    ASSESSED = "assessed"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    FAILED = "failed"
    REINVESTIGATING = "reinvestigating"


# ---------------------------------------------------------------------------
# Evidence provenance discipline
# ---------------------------------------------------------------------------
class AssertionClass(StrEnum):
    """Mandated separation of epistemic status.

    Every statement the platform stores or displays is tagged. Deterministic
    engines may consume OBSERVED_FACT freely; INFERENCE and RECOMMENDATION
    are never treated as ground truth by the risk or policy engines.
    """

    OBSERVED_FACT = "observed_fact"
    INFERENCE = "inference"
    RECOMMENDATION = "recommendation"


class EvidenceKind(StrEnum):
    TELEMETRY_WINDOW = "telemetry_window"
    NETWORK_FLOW_SET = "network_flow_set"
    AUTH_SEQUENCE = "auth_sequence"
    COMMAND_SEQUENCE = "command_sequence"
    DETECTOR_OUTPUT = "detector_output"
    DEVICE_STATE_SNAPSHOT = "device_state_snapshot"
    CORRELATION_RESULT = "correlation_result"


# ---------------------------------------------------------------------------
# Agentic layer
# ---------------------------------------------------------------------------
class AgentRole(StrEnum):
    INVESTIGATION = "investigation"
    THREAT_REASONING = "threat_reasoning"
    HEALTHCARE_CONTEXT = "healthcare_context"
    RESPONSE_PLANNING = "response_planning"
    RECOVERY_VERIFICATION = "recovery_verification"


class AgentRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    VALIDATION_FAILED = "validation_failed"
    ABORTED_AUTHORITY = "aborted_authority"


class ToolAuthority(StrEnum):
    """Authority classes for agent tools. Enforced by the tool registry."""

    READ_ONLY = "read_only"
    COMPUTE = "compute"
    REQUEST_APPROVAL = "request_approval"
    ACTUATE = "actuate"
    LEDGER_WRITE = "ledger_write"


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------
class RiskBand(StrEnum):
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


# ---------------------------------------------------------------------------
# Response and policy
# ---------------------------------------------------------------------------
class ResponseActionType(StrEnum):
    """Simulated response actions. Every member is actuatable in-simulator."""

    MONITOR_ONLY = "monitor_only"
    BLOCK_SOURCE_TRAFFIC = "block_source_traffic"
    RATE_LIMIT_TRAFFIC = "rate_limit_traffic"
    REVOKE_SESSION = "revoke_session"
    ROTATE_CREDENTIALS = "rotate_credentials"
    RESTRICT_COMMUNICATION = "restrict_communication"
    QUARANTINE_DEVICE = "quarantine_device"
    ISOLATE_NETWORK_SEGMENT = "isolate_network_segment"
    ACTIVATE_BACKUP_PATH = "activate_backup_path"
    FAILOVER_TO_REDUNDANT_DEVICE = "failover_to_redundant_device"
    RESTART_DEVICE_SERVICE = "restart_device_service"
    SHUTDOWN_DEVICE = "shutdown_device"
    ESCALATE_TO_CLINICAL_STAFF = "escalate_to_clinical_staff"


class ImpactClass(StrEnum):
    """Policy-relevant impact class of a candidate response."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    UNSAFE = "unsafe"


class PolicyDecision(StrEnum):
    AUTO_ALLOWED = "auto_allowed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"


class ResponseState(StrEnum):
    """Response state machine mandated by the specification."""

    PROPOSED = "proposed"
    POLICY_CHECK = "policy_check"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    AUTO_ALLOWED = "auto_allowed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    RECOVERY_CHECK = "recovery_check"
    RECOVERED = "recovered"
    RESIDUAL_RISK = "residual_risk"
    RESOLVED = "resolved"
    REINVESTIGATION = "reinvestigation"


class ApprovalStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class RecoveryOutcome(StrEnum):
    RECOVERED = "recovered"
    RESIDUAL_RISK = "residual_risk"
    FAILED = "failed"
    NEW_FAULT_INTRODUCED = "new_fault_introduced"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------
class ProvenanceEventType(StrEnum):
    INCIDENT_RECORDED = "incident_recorded"
    DECISION_RECORDED = "decision_recorded"
    APPROVAL_RECORDED = "approval_recorded"
    RESPONSE_RECORDED = "response_recorded"
    RECOVERY_RECORDED = "recovery_recorded"


class ProvenanceOrg(StrEnum):
    HOSPITAL = "HospitalMSP"
    SECURITY_OPS = "SecurityOpsMSP"
    AUDIT = "AuditMSP"


# ---------------------------------------------------------------------------
# Users / authorisation
# ---------------------------------------------------------------------------
class UserRole(StrEnum):
    VIEWER = "viewer"
    SOC_ANALYST = "soc_analyst"
    CLINICAL_APPROVER = "clinical_approver"
    ADMIN = "admin"


__all__ = [n for n in dir() if n[0].isupper()]
