"""`MockFabricClient` -- a `FabricClient` test double with no network, no
subprocess, no Fabric binaries.

This mirrors `blockchain/chaincode/lib/provenanceContract.js`'s own
validation rules (write-once `recordIncident`, append-only
decision/approval/response/recovery requiring an existing incident,
evidence-hash index for `verify_evidence`) rather than just recording calls
and returning canned success -- so a test using this double is actually
exercising the outbox worker's error handling (unknown incident, duplicate
incident, etc.), the same way the real chaincode would reject it. Keeping
this in sync with the chaincode's rules is a manual responsibility, flagged
here and in `blockchain/chaincode/README.md`: if you add a validation rule
to one, add it to the other.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from app.blockchain.fabric_client import FabricInvocationError, FabricTxResult

_RESPONSE_ACTION_CATEGORIES = {
    "block_traffic",
    "revoke_session",
    "rotate_credentials",
    "restrict_communication",
    "isolate_non_critical",
    "isolate_critical",
    "quarantine_segment",
    "activate_backup",
    "restart_service",
    "failover",
    "shutdown",
}
_APPROVAL_DECISIONS = {"approved", "rejected"}


@dataclass
class _IncidentState:
    incident: dict
    decisions: list[dict] = field(default_factory=list)
    approvals: list[dict] = field(default_factory=list)
    responses: list[dict] = field(default_factory=list)
    recoveries: list[dict] = field(default_factory=list)


class MockFabricClient:
    """In-memory stand-in for `FabricClient`. Each instance has its own
    isolated ledger (a plain dict) -- construct a fresh one per test."""

    def __init__(self) -> None:
        self._incidents: dict[str, _IncidentState] = {}
        self._evidence_hashes: set[str] = set()
        self._tx_counter = itertools.count(1)

    def _next_tx_id(self) -> str:
        return f"mock-tx-{next(self._tx_counter)}"

    def _require_incident(self, incident_id: str) -> _IncidentState:
        state = self._incidents.get(incident_id)
        if state is None:
            raise FabricInvocationError(
                f"incident '{incident_id}' has no recordIncident entry -- "
                "call recordIncident before recording a decision, approval, response, or recovery"
            )
        return state

    async def record_incident(
        self, incident_id: str, device_id: str, attack_type: str, evidence_hash: str, timestamp: str
    ) -> FabricTxResult:
        if incident_id in self._incidents:
            raise FabricInvocationError(
                f"incident '{incident_id}' already has a recordIncident entry -- "
                "the initial incident record cannot be overwritten"
            )
        tx_id = self._next_tx_id()
        record = {
            "incidentId": incident_id,
            "deviceId": device_id,
            "attackType": attack_type,
            "evidenceHash": evidence_hash,
            "timestamp": timestamp,
            "recordedTxId": tx_id,
        }
        self._incidents[incident_id] = _IncidentState(incident=record)
        self._evidence_hashes.add(evidence_hash)
        return FabricTxResult(tx_id=tx_id, payload=record)

    async def record_decision(
        self, incident_id: str, risk_score_hash: str, policy_rule_id: str, recommended_action: str
    ) -> FabricTxResult:
        if recommended_action not in _RESPONSE_ACTION_CATEGORIES:
            raise FabricInvocationError(
                f"recommended_action must be one of {sorted(_RESPONSE_ACTION_CATEGORIES)}, "
                f"got '{recommended_action}'"
            )
        state = self._require_incident(incident_id)
        tx_id = self._next_tx_id()
        record = {
            "incidentId": incident_id,
            "riskScoreHash": risk_score_hash,
            "policyRuleId": policy_rule_id,
            "recommendedAction": recommended_action,
            "recordedTxId": tx_id,
        }
        state.decisions.append(record)
        return FabricTxResult(tx_id=tx_id, payload=record)

    async def record_approval(
        self, incident_id: str, approver_identity: str, decision: str, timestamp: str
    ) -> FabricTxResult:
        if decision not in _APPROVAL_DECISIONS:
            raise FabricInvocationError(
                f"decision must be one of {sorted(_APPROVAL_DECISIONS)}, got '{decision}'"
            )
        state = self._require_incident(incident_id)
        tx_id = self._next_tx_id()
        record = {
            "incidentId": incident_id,
            "approverIdentity": approver_identity,
            "decision": decision,
            "timestamp": timestamp,
            "recordedTxId": tx_id,
        }
        state.approvals.append(record)
        return FabricTxResult(tx_id=tx_id, payload=record)

    async def record_response(
        self, incident_id: str, action_taken: str, executed_by: str, timestamp: str
    ) -> FabricTxResult:
        if action_taken not in _RESPONSE_ACTION_CATEGORIES:
            raise FabricInvocationError(
                f"action_taken must be one of {sorted(_RESPONSE_ACTION_CATEGORIES)}, got '{action_taken}'"
            )
        state = self._require_incident(incident_id)
        tx_id = self._next_tx_id()
        record = {
            "incidentId": incident_id,
            "actionTaken": action_taken,
            "executedBy": executed_by,
            "timestamp": timestamp,
            "recordedTxId": tx_id,
        }
        state.responses.append(record)
        return FabricTxResult(tx_id=tx_id, payload=record)

    async def record_recovery(
        self, incident_id: str, recovery_verified: bool, residual_threats_hash: str | None
    ) -> FabricTxResult:
        state = self._require_incident(incident_id)
        tx_id = self._next_tx_id()
        has_residual_hash = bool(residual_threats_hash)
        record = {
            "incidentId": incident_id,
            "recoveryVerified": recovery_verified,
            "residualThreatsHash": residual_threats_hash if has_residual_hash else None,
            "recordedTxId": tx_id,
        }
        state.recoveries.append(record)
        if has_residual_hash:
            self._evidence_hashes.add(residual_threats_hash)
        return FabricTxResult(tx_id=tx_id, payload=record)

    async def verify_evidence(self, evidence_hash: str) -> bool:
        return evidence_hash in self._evidence_hashes
