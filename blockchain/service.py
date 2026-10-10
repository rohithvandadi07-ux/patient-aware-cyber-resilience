"""Provenance service: the ledger's integration into the incident lifecycle.

The specification is explicit that blockchain must be "integrated into the
real incident lifecycle" and not "a separate demo". This module is that
integration: it builds the five mandated provenance records from live
incident state at the moment each lifecycle event occurs, and nothing else
in the platform constructs a ledger record.

Each builder takes the authoritative objects and emits a *small* record —
identifiers, hashes, verdicts, timestamps. The engine fingerprints
(``formulation_version``, ``policy_version``) are included deliberately: a
provenance entry that records a decision but not the parameter set that
produced it cannot be audited later, because the same inputs under a
different profile would yield a different decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.app.domain.enums import ProvenanceEventType, ProvenanceOrg
from backend.app.domain.ids import Clock, IdFactory, canonical_hash
from backend.app.domain.models import (
    ApprovalRecord,
    Incident,
    LedgerReceipt,
    PatientAwareDecision,
    ProvenanceRecord,
    RecoveryResult,
    ResponseRecord,
)
from blockchain.adapter.interface import ProvenanceLedger, VerificationResult


@dataclass
class ProvenanceService:
    """Builds and commits provenance records at lifecycle boundaries."""

    ledger: ProvenanceLedger
    ids: IdFactory
    clock: Clock
    #: Fingerprints of the active engine configurations, recorded on every
    #: decision so a published number is traceable to its parameters.
    risk_profile_fingerprint: str = ""
    policy_fingerprint: str = ""
    _receipts: dict[str, list[LedgerReceipt]] = field(default_factory=dict, init=False)

    # -- the five mandated records ----------------------------------------
    def record_incident(self, incident: Incident) -> LedgerReceipt:
        """INCIDENT_RECORDED: an incident was opened, with its evidence hash."""
        detection = incident.detection
        record = ProvenanceRecord(
            provenance_id=self.ids.provenance(),
            event_type=ProvenanceEventType.INCIDENT_RECORDED,
            incident_id=incident.incident_id,
            device_id=incident.device_id,
            timestamp=self.clock.now(),
            evidence_hash=incident.evidence_bundle_hash(),
            detector_result_hash=(
                canonical_hash(
                    {
                        "detector": detection.detector_name,
                        "model_version": detection.model_version,
                        "attack_type": detection.attack_type.value,
                        "confidence": detection.confidence,
                    }
                )
                if detection
                else None
            ),
            risk_summary={},
            submitting_org=ProvenanceOrg.SECURITY_OPS.value,
        )
        return self._commit(incident.incident_id, record)

    def record_decision(self, incident_id: str, decision: PatientAwareDecision) -> LedgerReceipt:
        """DECISION_RECORDED: the patient-aware decision and its counterfactual.

        The counterfactual is committed because it is the contribution's
        evidence: a reader can later verify that the system considered — and
        declined — the action a cyber-only defender would have taken.
        """
        record = ProvenanceRecord(
            provenance_id=self.ids.provenance(),
            event_type=ProvenanceEventType.DECISION_RECORDED,
            incident_id=incident_id,
            timestamp=self.clock.now(),
            risk_summary={
                "cyber_risk": decision.cyber_risk.score,
                "cyber_uncertainty": decision.cyber_risk.uncertainty,
                "clinical_risk": decision.clinical_risk.score,
                "clinical_uncertainty": decision.clinical_risk.uncertainty,
                "decision_score": decision.decision_score,
            },
            agent_decision=(
                f"patient_aware:{decision.selected_action.value}"
                f"|cyber_only:{decision.cyber_only_action.value}"
                f"|diverged:{decision.diverged_from_cyber_only}"
                if decision.cyber_only_action
                else f"patient_aware:{decision.selected_action.value}"
            ),
            recommended_action=decision.selected_action.value,
            formulation_version=(
                f"{decision.formulation_version}@{self.risk_profile_fingerprint}"
                if self.risk_profile_fingerprint
                else decision.formulation_version
            ),
            submitting_org=ProvenanceOrg.SECURITY_OPS.value,
        )
        return self._commit(incident_id, record)

    def record_approval(self, incident_id: str, approval: ApprovalRecord) -> LedgerReceipt:
        """APPROVAL_RECORDED: who authorised what, and when."""
        record = ProvenanceRecord(
            provenance_id=self.ids.provenance(),
            event_type=ProvenanceEventType.APPROVAL_RECORDED,
            incident_id=incident_id,
            timestamp=self.clock.now(),
            approval_status=approval.status.value,
            approver=approval.approver,
            policy_version=self.policy_fingerprint or None,
            # The justification is hashed rather than stored: it is free text
            # that may name staff, and an immutable replicated ledger is the
            # wrong place for it. The hash still proves it has not changed.
            evidence_hash=canonical_hash(
                {
                    "approval_id": approval.approval_id,
                    "required_role": approval.required_role,
                    "justification": approval.justification,
                }
            ),
            submitting_org=ProvenanceOrg.HOSPITAL.value,
        )
        return self._commit(incident_id, record)

    def record_response(self, incident_id: str, response: ResponseRecord) -> LedgerReceipt:
        """RESPONSE_RECORDED: what was executed, under which policy verdict."""
        policy = response.policy
        record = ProvenanceRecord(
            provenance_id=self.ids.provenance(),
            event_type=ProvenanceEventType.RESPONSE_RECORDED,
            incident_id=incident_id,
            device_id=response.candidate.target_device_id,
            timestamp=self.clock.now(),
            executed_action=response.candidate.action_type.value,
            execution_result=(
                f"{response.state.value}"
                f"|succeeded:{response.execution_succeeded}"
                f"|attempt:{response.attempt_number}"
            ),
            approval_status=(
                response.approval.status.value if response.approval else "not_required"
            ),
            approver=response.approval.approver if response.approval else None,
            policy_version=(
                f"{policy.policy_version}@{self.policy_fingerprint}"
                if policy and self.policy_fingerprint
                else (policy.policy_version if policy else None)
            ),
            agent_decision=(
                f"policy:{policy.decision.value}|rule:{policy.matched_rule}" if policy else None
            ),
            submitting_org=ProvenanceOrg.SECURITY_OPS.value,
        )
        return self._commit(incident_id, record)

    def record_recovery(self, incident_id: str, recovery: RecoveryResult) -> LedgerReceipt:
        """RECOVERY_RECORDED: whether the response actually worked."""
        record = ProvenanceRecord(
            provenance_id=self.ids.provenance(),
            event_type=ProvenanceEventType.RECOVERY_RECORDED,
            incident_id=incident_id,
            timestamp=self.clock.now(),
            recovery_result=(
                f"{recovery.outcome.value}"
                f"|checks:{recovery.checks_passed}/{len(recovery.checks)}"
                f"|reinvestigate:{recovery.requires_reinvestigation}"
            ),
            risk_summary={"residual_risk": recovery.residual_risk},
            evidence_hash=canonical_hash(
                {
                    "recovery_id": recovery.recovery_id,
                    "response_id": recovery.response_id,
                    "checks": [{"name": c.name, "passed": c.passed} for c in recovery.checks],
                }
            ),
            submitting_org=ProvenanceOrg.AUDIT.value,
        )
        return self._commit(incident_id, record)

    # -- verification ------------------------------------------------------
    def verify_incident_evidence(self, incident: Incident) -> dict[str, Any]:
        """Check the incident's evidence against what was committed.

        Two independent checks, deliberately separated because they fail for
        different reasons: the off-chain evidence may have been altered
        (``evidence_intact``), or the ledger itself may have been tampered
        with (``chain_valid``).
        """
        per_item = {e.evidence_id: e.verify() for e in incident.evidence}
        bundle_hash = incident.evidence_bundle_hash()

        committed = [
            r
            for r in self.ledger.history(incident.incident_id)
            if r.get("event_type") == ProvenanceEventType.INCIDENT_RECORDED.value
        ]
        committed_hash = str(committed[0]["payload"].get("evidence_hash", "")) if committed else ""
        chain = self.ledger.verify_chain()

        return {
            "incident_id": incident.incident_id,
            "evidence_items": len(per_item),
            "evidence_intact": all(per_item.values()),
            "failed_items": sorted(k for k, v in per_item.items() if not v),
            "bundle_hash": bundle_hash,
            "committed_bundle_hash": committed_hash,
            "bundle_matches_ledger": bool(committed_hash) and committed_hash == bundle_hash,
            "chain_valid": chain.valid,
            "chain_detail": chain.detail,
            "records_committed": len(self.ledger.history(incident.incident_id)),
        }

    def verify_chain(self) -> VerificationResult:
        return self.ledger.verify_chain()

    def audit_trail(self, incident_id: str) -> list[dict[str, Any]]:
        """Full committed provenance for one incident, in commit order."""
        return self.ledger.history(incident_id)

    def receipts(self, incident_id: str) -> list[LedgerReceipt]:
        return list(self._receipts.get(incident_id, []))

    def stats(self):
        return self.ledger.stats()

    # -- internals ---------------------------------------------------------
    def _commit(self, incident_id: str, record: ProvenanceRecord) -> LedgerReceipt:
        receipt = self.ledger.record(record)
        self._receipts.setdefault(incident_id, []).append(receipt)
        return receipt


__all__ = ["ProvenanceService"]
