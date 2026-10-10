"""Provenance ledger tests.

Two properties matter most and are tested directly rather than inspected:

* **Payload hygiene.** Patient context, raw telemetry and evidence bodies
  must never reach a ledger that is replicated to every organisation and
  immutable. Rejected, not filtered, so a design error in the caller fails
  loudly.
* **Tamper detection.** Altering a committed record must invalidate the
  chain and identify where it broke.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from backend.app.domain.enums import (
    ApprovalStatus,
    AttackType,
    DetectorKind,
    EvidenceKind,
    ImpactClass,
    PolicyDecision,
    ProvenanceEventType,
    ProvenanceOrg,
    RecoveryOutcome,
    ResponseActionType,
    ResponseState,
    Severity,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    ApprovalRecord,
    ClinicalRiskResult,
    CyberRiskResult,
    DetectionResult,
    EvidenceRef,
    Incident,
    PatientAwareDecision,
    PolicyEvaluation,
    ProvenanceRecord,
    RecoveryCheck,
    RecoveryResult,
    ResponseCandidate,
    ResponseRecord,
)
from blockchain import (
    FORBIDDEN_LEDGER_KEYS,
    MAX_RECORD_BYTES,
    FabricConfig,
    FabricProvenanceLedger,
    LedgerError,
    LedgerIntegrityError,
    LedgerPayloadRejected,
    LocalProvenanceLedger,
    ProvenanceService,
    build_ledger,
)
from blockchain.adapter.fabric_gateway import CHAINCODE_FUNCTIONS

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


class SteppingClock(Clock):
    def __init__(self) -> None:
        self._t = T0

    def now(self) -> datetime:
        self._t += timedelta(seconds=1)
        return self._t


@pytest.fixture
def ledger(tmp_path) -> LocalProvenanceLedger:
    return LocalProvenanceLedger(
        path=tmp_path / "ledger.jsonl",
        ids=IdFactory(deterministic=True),
        clock=SteppingClock(),
    )


@pytest.fixture
def service(ledger) -> ProvenanceService:
    return ProvenanceService(
        ledger=ledger,
        ids=IdFactory(deterministic=True),
        clock=SteppingClock(),
        risk_profile_fingerprint="risk-abc123",
        policy_fingerprint="policy-def456",
    )


def _evidence(n: int = 3) -> list[EvidenceRef]:
    return [
        EvidenceRef(
            evidence_id=f"EVD-{i:06d}",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=T0,
            produced_by="test_detector",
            payload={"index": i, "detail": "off-chain evidence body"},
        ).with_hash()
        for i in range(n)
    ]


def _incident() -> Incident:
    detection = DetectionResult(
        detector_name="rf",
        detector_kind=DetectorKind.SUPERVISED_CLASSIFIER,
        model_version="rf-v1",
        timestamp=T0,
        device_id="VENT-ICU-01",
        is_attack=True,
        attack_type=AttackType.MALICIOUS_COMMAND,
        confidence=0.91,
        severity=Severity.CRITICAL,
    )
    return Incident(
        incident_id="INC-000001",
        created_at=T0,
        updated_at=T0,
        device_id="VENT-ICU-01",
        attack_type=AttackType.MALICIOUS_COMMAND,
        confidence=0.91,
        severity=Severity.CRITICAL,
        detection=detection,
        evidence=_evidence(),
    )


def _record(
    event_type: ProvenanceEventType = ProvenanceEventType.INCIDENT_RECORDED,
    provenance_id: str = "PRV-000001",
) -> ProvenanceRecord:
    return ProvenanceRecord(
        provenance_id=provenance_id,
        event_type=event_type,
        incident_id="INC-000001",
        device_id="VENT-ICU-01",
        timestamp=T0,
        evidence_hash="abc123def456",
        submitting_org=ProvenanceOrg.SECURITY_OPS.value,
    )


# ===========================================================================
# Payload hygiene
# ===========================================================================
class TestPayloadHygiene:
    def test_patient_context_is_rejected(self, ledger) -> None:
        """An immutable replicated ledger is the wrong place for this."""
        payload = _record().payload_for_ledger()
        payload["patient"] = {"patient_ref": "SYN-PT-0001", "acuity": "critical"}
        with pytest.raises(LedgerPayloadRejected, match="forbidden keys"):
            ledger.validate_payload(payload)

    @pytest.mark.parametrize("key", sorted(FORBIDDEN_LEDGER_KEYS))
    def test_every_forbidden_key_is_rejected(self, ledger, key: str) -> None:
        payload = _record().payload_for_ledger()
        payload[key] = {"anything": "at all"}
        with pytest.raises(LedgerPayloadRejected):
            ledger.validate_payload(payload)

    def test_rejection_explains_why(self, ledger) -> None:
        payload = _record().payload_for_ledger()
        payload["telemetry"] = [1, 2, 3]
        with pytest.raises(LedgerPayloadRejected) as exc:
            ledger.validate_payload(payload)
        message = str(exc.value)
        assert "off-chain" in message
        assert "immutable" in message

    def test_forbidden_data_is_rejected_not_silently_filtered(self, ledger) -> None:
        """Filtering would hide a design error in the caller."""
        payload = _record().payload_for_ledger()
        payload["payload"] = {"bulk": "x" * 100}
        with pytest.raises(LedgerPayloadRejected):
            ledger.validate_payload(payload)

    def test_oversized_record_is_rejected(self, ledger) -> None:
        payload = _record().payload_for_ledger()
        payload["notes"] = "x" * (MAX_RECORD_BYTES + 1)
        with pytest.raises(LedgerPayloadRejected, match="limit"):
            ledger.validate_payload(payload)

    def test_provenance_record_strips_bulk_by_construction(self) -> None:
        payload = _record().payload_for_ledger()
        assert not (set(payload) & FORBIDDEN_LEDGER_KEYS)

    def test_committed_records_stay_small(self, service) -> None:
        """Storage overhead is a reported metric; it must stay bounded."""
        incident = _incident()
        service.record_incident(incident)
        stats = service.stats()
        assert stats.mean_record_bytes < MAX_RECORD_BYTES
        assert stats.record_count == 1

    def test_evidence_body_stays_off_chain(self, service, ledger) -> None:
        """Only the hash is committed; the payload is not."""
        incident = _incident()
        service.record_incident(incident)
        committed = json.dumps(ledger.all_blocks())
        assert "off-chain evidence body" not in committed
        assert incident.evidence_bundle_hash() in committed


# ===========================================================================
# Hash chain and tamper detection
# ===========================================================================
class TestHashChain:
    def test_genesis_block_links_to_zero(self, ledger) -> None:
        receipt = ledger.record(_record())
        assert receipt.block_number == 0
        assert receipt.previous_hash == "0" * 64

    def test_blocks_chain_to_their_predecessor(self, ledger) -> None:
        first = ledger.record(_record(provenance_id="PRV-000001"))
        second = ledger.record(_record(ProvenanceEventType.DECISION_RECORDED, "PRV-000002"))
        assert second.previous_hash == first.record_hash
        assert second.block_number == 1

    def test_clean_chain_verifies(self, ledger) -> None:
        for i in range(5):
            ledger.record(_record(provenance_id=f"PRV-{i:06d}"))
        result = ledger.verify_chain()
        assert result.valid is True
        assert result.checked == 5
        assert result.broken_links == []

    def test_altering_a_record_breaks_the_chain(self, ledger) -> None:
        for i in range(5):
            ledger.record(_record(provenance_id=f"PRV-{i:06d}"))
        assert ledger.verify_chain().valid is True

        ledger.tamper_for_test(2, "evidence_hash", "tampered")
        result = ledger.verify_chain()
        assert result.valid is False
        assert result.first_invalid_index == 2
        assert "altered after commit" in result.detail

    def test_tampering_identifies_the_exact_block(self, ledger) -> None:
        for i in range(4):
            ledger.record(_record(provenance_id=f"PRV-{i:06d}"))
        ledger.tamper_for_test(1, "incident_id", "INC-FORGED")
        result = ledger.verify_chain()
        assert result.first_invalid_index == 1
        assert "PRV-000001" in result.detail

    def test_rewriting_a_committed_id_is_refused(self, ledger) -> None:
        ledger.record(_record(provenance_id="PRV-000001"))
        with pytest.raises(LedgerError, match="append-only"):
            ledger.record(_record(provenance_id="PRV-000001"))

    def test_broken_chain_is_refused_on_reload(self, tmp_path) -> None:
        """Appending to a known-broken chain would hide the tampering."""
        path = tmp_path / "ledger.jsonl"
        first = LocalProvenanceLedger(
            path=path, ids=IdFactory(deterministic=True), clock=SteppingClock()
        )
        for i in range(3):
            first.record(_record(provenance_id=f"PRV-{i:06d}"))

        lines = path.read_text(encoding="utf-8").splitlines()
        block = json.loads(lines[1])
        block["payload"]["evidence_hash"] = "forged"
        lines[1] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(LedgerIntegrityError, match="Refusing to append"):
            LocalProvenanceLedger(
                path=path, ids=IdFactory(deterministic=True), clock=SteppingClock()
            )

    def test_malformed_ledger_file_is_detected(self, tmp_path) -> None:
        path = tmp_path / "ledger.jsonl"
        path.write_text("not json at all\n", encoding="utf-8")
        with pytest.raises(LedgerIntegrityError, match="not a valid ledger block"):
            LocalProvenanceLedger(
                path=path, ids=IdFactory(deterministic=True), clock=SteppingClock()
            )

    def test_ledger_survives_a_restart(self, tmp_path) -> None:
        path = tmp_path / "ledger.jsonl"
        first = LocalProvenanceLedger(
            path=path, ids=IdFactory(deterministic=True), clock=SteppingClock()
        )
        for i in range(3):
            first.record(_record(provenance_id=f"PRV-{i:06d}"))

        reopened = LocalProvenanceLedger(
            path=path, ids=IdFactory(deterministic=True), clock=SteppingClock()
        )
        assert reopened.verify_chain().valid is True
        assert len(reopened.all_blocks()) == 3
        receipt = reopened.record(_record(provenance_id="PRV-000003"))
        assert receipt.block_number == 3


# ===========================================================================
# Evidence verification
# ===========================================================================
class TestEvidenceVerification:
    def test_matching_hash_verifies(self, ledger) -> None:
        ledger.record(_record())
        assert ledger.verify_evidence("PRV-000001", "abc123def456") is True

    def test_wrong_hash_fails(self, ledger) -> None:
        ledger.record(_record())
        assert ledger.verify_evidence("PRV-000001", "wrong") is False

    def test_missing_record_is_not_a_pass(self, ledger) -> None:
        """A caller must not read 'not found' as verified."""
        assert ledger.verify_evidence("PRV-NOPE", "abc123def456") is False

    def test_clean_evidence_passes_both_checks(self, service) -> None:
        incident = _incident()
        service.record_incident(incident)
        clean = service.verify_incident_evidence(incident)
        assert clean["evidence_intact"] is True
        assert clean["bundle_matches_ledger"] is True

    def test_altered_evidence_body_is_caught_by_per_item_verification(self, service) -> None:
        """Two checks catch two different attacks.

        Per-item ``verify()`` recomputes each evidence hash from its payload,
        so it catches an ALTERED body. The bundle hash is computed over the
        evidence_hash fields, so it catches evidence being ADDED or REMOVED.
        An attacker who alters a payload while leaving the stale hash field
        in place is caught by the first check, not the second - these are
        deliberately separate layers, and conflating them would leave one of
        the two attacks undetected.
        """
        incident = _incident()
        service.record_incident(incident)
        tampered = incident.model_copy(
            update={
                "evidence": [
                    incident.evidence[0].model_copy(
                        update={"payload": {"index": 0, "detail": "ALTERED"}}
                    ),
                    *incident.evidence[1:],
                ]
            }
        )
        result = service.verify_incident_evidence(tampered)
        assert result["evidence_intact"] is False
        assert "EVD-000000" in result["failed_items"]

    def test_removed_evidence_is_caught_by_the_bundle_hash(self, service) -> None:
        """Dropping inconvenient evidence must not pass unnoticed."""
        incident = _incident()
        service.record_incident(incident)
        pruned = incident.model_copy(update={"evidence": incident.evidence[:-1]})
        result = service.verify_incident_evidence(pruned)
        assert result["evidence_intact"] is True, "the remaining items are individually intact"
        assert result["bundle_matches_ledger"] is False, (
            "but the bundle no longer matches what was committed"
        )

    def test_added_evidence_is_caught_by_the_bundle_hash(self, service) -> None:
        """Nor must evidence be inserted after the fact."""
        incident = _incident()
        service.record_incident(incident)
        extra = EvidenceRef(
            evidence_id="EVD-999999",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=T0,
            produced_by="injected",
            payload={"fabricated": True},
        ).with_hash()
        inflated = incident.model_copy(update={"evidence": [*incident.evidence, extra]})
        result = service.verify_incident_evidence(inflated)
        assert result["evidence_intact"] is True
        assert result["bundle_matches_ledger"] is False

    def test_rehashed_tampering_is_still_caught_by_the_bundle(self, service) -> None:
        """A sophisticated attacker re-hashes; the bundle still catches it.

        Altering a payload AND recomputing its hash defeats per-item
        verification - but changes the evidence_hash field, so the bundle no
        longer matches the committed one. The two layers close each other's
        gap, which is why both exist.
        """
        incident = _incident()
        service.record_incident(incident)
        rehashed = (
            incident.evidence[0]
            .model_copy(update={"payload": {"index": 0, "detail": "ALTERED"}})
            .with_hash()
        )
        tampered = incident.model_copy(update={"evidence": [rehashed, *incident.evidence[1:]]})
        result = service.verify_incident_evidence(tampered)
        assert result["evidence_intact"] is True, "re-hashing defeats per-item verification"
        assert result["bundle_matches_ledger"] is False, (
            "but the committed bundle hash does not match"
        )

    def test_evidence_and_chain_checks_are_independent(self, service, ledger) -> None:
        """They fail for different reasons and must be reported separately."""
        incident = _incident()
        service.record_incident(incident)
        ledger.tamper_for_test(0, "incident_id", "INC-FORGED")
        result = service.verify_incident_evidence(incident)
        assert result["evidence_intact"] is True
        assert result["chain_valid"] is False


# ===========================================================================
# Lifecycle integration
# ===========================================================================
class TestLifecycleIntegration:
    def _decision(self) -> PatientAwareDecision:
        return PatientAwareDecision(
            incident_id="INC-000001",
            decided_at=T0,
            cyber_risk=CyberRiskResult(score=0.74, uncertainty=0.13),
            clinical_risk=ClinicalRiskResult(score=1.0, life_support_involved=True),
            selected_action=ResponseActionType.ROTATE_CREDENTIALS,
            decision_score=0.22,
            cyber_only_action=ResponseActionType.SHUTDOWN_DEVICE,
            diverged_from_cyber_only=True,
            divergence_reason="shutdown would interrupt life-sustaining therapy",
        )

    def _response(self) -> ResponseRecord:
        return ResponseRecord(
            response_id="RSP-000001",
            incident_id="INC-000001",
            candidate=ResponseCandidate(
                action_type=ResponseActionType.ROTATE_CREDENTIALS,
                target_device_id="VENT-ICU-01",
            ),
            state=ResponseState.EXECUTED,
            policy=PolicyEvaluation(
                action_type=ResponseActionType.ROTATE_CREDENTIALS,
                decision=PolicyDecision.APPROVAL_REQUIRED,
                impact_class=ImpactClass.MODERATE,
                matched_rule="approval_for_high_clinical_risk",
                policy_version="v1",
            ),
            approval=ApprovalRecord(
                approval_id="APR-000001",
                incident_id="INC-000001",
                response_id="RSP-000001",
                status=ApprovalStatus.APPROVED,
                requested_at=T0,
                approver="clinician-01",
            ),
            proposed_at=T0,
            executed_at=T0,
            execution_succeeded=True,
        )

    def _recovery(self) -> RecoveryResult:
        return RecoveryResult(
            recovery_id="RCV-000001",
            incident_id="INC-000001",
            response_id="RSP-000001",
            verified_at=T0,
            outcome=RecoveryOutcome.RECOVERED,
            checks=[
                RecoveryCheck(name="anomaly_cleared", passed=True),
                RecoveryCheck(name="attack_mechanism_severed", passed=True),
            ],
            residual_risk=0.02,
        )

    def test_all_five_mandated_records_commit(self, service) -> None:
        incident = _incident()
        service.record_incident(incident)
        service.record_decision(incident.incident_id, self._decision())
        service.record_approval(incident.incident_id, self._response().approval)
        service.record_response(incident.incident_id, self._response())
        service.record_recovery(incident.incident_id, self._recovery())

        trail = service.audit_trail(incident.incident_id)
        assert len(trail) == 5
        assert {r["event_type"] for r in trail} == {e.value for e in ProvenanceEventType}

    def test_audit_trail_is_in_commit_order(self, service) -> None:
        incident = _incident()
        service.record_incident(incident)
        service.record_decision(incident.incident_id, self._decision())
        service.record_response(incident.incident_id, self._response())
        trail = service.audit_trail(incident.incident_id)
        assert [r["index"] for r in trail] == sorted(r["index"] for r in trail)

    def test_decision_record_commits_the_counterfactual(self, service) -> None:
        """The contribution's evidence must be independently checkable."""
        service.record_decision("INC-000001", self._decision())
        trail = service.audit_trail("INC-000001")
        payload = trail[0]["payload"]
        assert "cyber_only:shutdown_device" in payload["agent_decision"]
        assert "diverged:True" in payload["agent_decision"]
        assert payload["recommended_action"] == "rotate_credentials"

    def test_decision_record_commits_the_parameter_fingerprint(self, service) -> None:
        """A decision without its parameters cannot be audited later."""
        service.record_decision("INC-000001", self._decision())
        payload = service.audit_trail("INC-000001")[0]["payload"]
        assert "risk-abc123" in payload["formulation_version"]

    def test_response_record_commits_the_policy_verdict(self, service) -> None:
        service.record_response("INC-000001", self._response())
        payload = service.audit_trail("INC-000001")[0]["payload"]
        assert "approval_for_high_clinical_risk" in payload["agent_decision"]
        assert "policy-def456" in payload["policy_version"]

    def test_approval_record_names_the_approver(self, service) -> None:
        service.record_approval("INC-000001", self._response().approval)
        payload = service.audit_trail("INC-000001")[0]["payload"]
        assert payload["approver"] == "clinician-01"
        assert payload["approval_status"] == "approved"

    def test_approval_justification_is_hashed_not_stored(self, service) -> None:
        """Free text may name staff; a replicated ledger is the wrong home."""
        approval = self._response().approval.model_copy(
            update={"justification": "Dr Smith on ward 4 authorised this"}
        )
        service.record_approval("INC-000001", approval)
        committed = json.dumps(service.audit_trail("INC-000001"))
        assert "Dr Smith" not in committed
        assert service.audit_trail("INC-000001")[0]["payload"]["evidence_hash"]

    def test_organisations_are_separated_by_record_type(self, service) -> None:
        """Separation of duties: the auditor does not originate decisions."""
        incident = _incident()
        service.record_incident(incident)
        service.record_approval(incident.incident_id, self._response().approval)
        service.record_recovery(incident.incident_id, self._recovery())
        trail = {
            r["event_type"]: r["submitting_org"] for r in service.audit_trail(incident.incident_id)
        }
        assert trail["incident_recorded"] == ProvenanceOrg.SECURITY_OPS.value
        assert trail["approval_recorded"] == ProvenanceOrg.HOSPITAL.value
        assert trail["recovery_recorded"] == ProvenanceOrg.AUDIT.value

    def test_receipts_are_retained_per_incident(self, service) -> None:
        incident = _incident()
        service.record_incident(incident)
        service.record_decision(incident.incident_id, self._decision())
        receipts = service.receipts(incident.incident_id)
        assert len(receipts) == 2
        assert all(r.backend == "local" for r in receipts)
        assert all(r.record_hash for r in receipts)


# ===========================================================================
# Metrics
# ===========================================================================
class TestLedgerMetrics:
    def test_stats_report_the_backend(self, service) -> None:
        """Every metric must be attributable to the backend that produced it."""
        service.record_incident(_incident())
        stats = service.stats()
        assert stats.backend == "local"

    def test_stats_report_latency_and_storage(self, ledger) -> None:
        for i in range(20):
            ledger.record(_record(provenance_id=f"PRV-{i:06d}"))
        stats = ledger.stats()
        assert stats.record_count == 20
        assert stats.mean_latency_ms > 0
        assert stats.p95_latency_ms >= stats.mean_latency_ms * 0.5
        assert stats.total_bytes > 0
        assert stats.storage_overhead_bytes_per_record > 0
        assert stats.verification_ms is not None


# ===========================================================================
# Backend selection and Fabric adapter
# ===========================================================================
class TestBackendSelection:
    def test_default_backend_is_local(self, tmp_path, monkeypatch) -> None:
        monkeypatch.delenv("PROVENANCE_BACKEND", raising=False)
        led = build_ledger(IdFactory(deterministic=True), SteppingClock(), path=tmp_path)
        assert led.backend_name == "local"

    def test_unknown_backend_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown provenance backend"):
            build_ledger(IdFactory(deterministic=True), SteppingClock(), backend="ethereum")

    def test_fabric_requires_identity_material(self, monkeypatch) -> None:
        for var in ("FABRIC_CERT_PATH", "FABRIC_KEY_PATH", "FABRIC_TLS_CA_PATH"):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(LedgerError, match="identity material"):
            FabricConfig.from_env().validate()

    def test_fabric_connect_refuses_rather_than_half_configuring(self, monkeypatch) -> None:
        """An honest refusal beats a client that fails later, obscurely."""
        from blockchain.adapter.fabric_gateway import connect_fabric

        for var, value in (
            ("FABRIC_CERT_PATH", "/secure/cert.pem"),
            ("FABRIC_KEY_PATH", "/secure/key.pem"),
            ("FABRIC_TLS_CA_PATH", "/secure/ca.crt"),
        ):
            monkeypatch.setenv(var, value)
        with pytest.raises(LedgerError):
            connect_fabric(SteppingClock())

    def test_every_event_type_maps_to_a_chaincode_function(self) -> None:
        for event in ProvenanceEventType:
            assert event.value in CHAINCODE_FUNCTIONS, f"{event.value} has no chaincode function"


class TestFabricAdapterLogic:
    """Adapter logic against a stub gateway.

    These verify the ADAPTER - payload hygiene, receipt construction, error
    translation - not Fabric. Fabric's behaviour needs a live network; see
    docs/blockchain.md.
    """

    class _StubContract:
        def __init__(self, fail: bool = False) -> None:
            self.fail = fail
            self.submitted: list[tuple] = []

        def submit_transaction(self, name: str, *args: str) -> bytes:
            if self.fail:
                raise RuntimeError("endorsement policy failure")
            self.submitted.append((name, *args))
            return json.dumps(
                {
                    "txId": "abc123",
                    "blockNumber": len(self.submitted),
                    "recordHash": "f" * 64,
                }
            ).encode()

        def evaluate_transaction(self, name: str, *args: str) -> bytes:
            if name == "verifyEvidence":
                return json.dumps({"valid": args[1] == "abc123def456"}).encode()
            if name == "getChainInfo":
                return json.dumps({"height": len(self.submitted)}).encode()
            if name == "getIncidentHistory":
                return json.dumps([{"incident_id": args[0]}]).encode()
            return json.dumps({"provenance_id": args[0]}).encode()

    def _ledger(self, fail: bool = False) -> FabricProvenanceLedger:
        return FabricProvenanceLedger(contract=self._StubContract(fail=fail), clock=SteppingClock())

    def test_record_invokes_the_right_chaincode_function(self) -> None:
        led = self._ledger()
        led.record(_record(ProvenanceEventType.DECISION_RECORDED, "PRV-000001"))
        assert led.contract.submitted[0][0] == "recordDecision"

    def test_receipt_carries_the_fabric_backend(self) -> None:
        receipt = self._ledger().record(_record())
        assert receipt.backend == "fabric"
        assert receipt.transaction_id == "abc123"
        assert receipt.block_number == 1

    def test_payload_hygiene_applies_to_fabric_too(self) -> None:
        led = self._ledger()
        record = _record()
        bad = record.model_copy(update={"agent_decision": "x" * (MAX_RECORD_BYTES + 1)})
        with pytest.raises(LedgerPayloadRejected):
            led.record(bad)

    def test_sdk_error_is_translated(self) -> None:
        with pytest.raises(LedgerError, match="Fabric transaction"):
            self._ledger(fail=True).record(_record())

    def test_verify_evidence_round_trip(self) -> None:
        led = self._ledger()
        led.record(_record())
        assert led.verify_evidence("PRV-000001", "abc123def456") is True
        assert led.verify_evidence("PRV-000001", "wrong") is False

    def test_verify_chain_reports_the_peer_view_honestly(self) -> None:
        led = self._ledger()
        led.record(_record())
        result = led.verify_chain()
        assert result.valid is True
        assert "peer's view" in result.detail
        assert "not an independent client-side" in result.detail

    def test_stats_report_fabric_backend(self) -> None:
        led = self._ledger()
        led.record(_record())
        assert led.stats().backend == "fabric"


@pytest.mark.fabric
class TestAgainstLiveFabric:
    """Skipped unless a Fabric network is reachable.

    Present rather than absent so the gap is visible in the test report
    instead of being silently missing.
    """

    def test_live_network_round_trip(self) -> None:
        pytest.skip(
            "requires a running Hyperledger Fabric network; see "
            "docs/blockchain.md for the reproduction steps"
        )
