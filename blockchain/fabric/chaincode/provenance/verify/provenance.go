// Package main implements the Patient-Aware Cyber-Resilience provenance
// chaincode for Hyperledger Fabric.
//
// # WHAT THIS CHAINCODE COMMITS, AND WHAT IT REFUSES
//
// Only identifiers, hashes, verdicts and timestamps. The chaincode actively
// REJECTS payloads carrying raw telemetry, evidence bodies or patient
// context, rather than trusting the client to have stripped them.
//
// That check belongs here, on-chain, and not only in the client: a Fabric
// ledger is replicated to every organisation on the channel and is
// immutable, so a single careless client write would place patient context
// permanently on every peer with no way to delete or withhold it. The
// endorsing peer is the last place that can say no.
//
// Records are append-only. recordX functions refuse to overwrite an
// existing provenance id, so an incident's history cannot be rewritten
// after the fact — which is the entire point of putting it on a ledger.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ccverify/contractapi"
)

// maxRecordBytes mirrors the client-side limit in
// blockchain/adapter/interface.py. A record above this is almost certainly
// carrying bulk data that belongs off-chain.
const maxRecordBytes = 4096

// forbiddenKeys must never appear in a committed payload. Kept in step with
// FORBIDDEN_LEDGER_KEYS in blockchain/adapter/interface.py.
var forbiddenKeys = []string{
	"payload",
	"patient",
	"patient_ref",
	"telemetry",
	"events",
	"measurements",
	"raw",
	"evidence_payload",
	"model_artifact",
	"feature_matrix",
	"synthetic_patient_context",
}

// ProvenanceContract is the chaincode's smart contract.
type ProvenanceContract struct {
	contractapi.Contract
}

// ProvenanceEntry is one committed record. Field names match the Python
// ProvenanceRecord.payload_for_ledger() output so client and chaincode
// agree on the wire format.
type ProvenanceEntry struct {
	ProvenanceID       string             `json:"provenance_id"`
	EventType          string             `json:"event_type"`
	IncidentID         string             `json:"incident_id"`
	DeviceID           string             `json:"device_id,omitempty"`
	Timestamp          string             `json:"timestamp"`
	EvidenceHash       string             `json:"evidence_hash,omitempty"`
	DetectorResultHash string             `json:"detector_result_hash,omitempty"`
	RiskSummary        map[string]float64 `json:"risk_summary,omitempty"`
	AgentDecision      string             `json:"agent_decision,omitempty"`
	RecommendedAction  string             `json:"recommended_action,omitempty"`
	ApprovalStatus     string             `json:"approval_status,omitempty"`
	Approver           string             `json:"approver,omitempty"`
	ExecutedAction     string             `json:"executed_action,omitempty"`
	ExecutionResult    string             `json:"execution_result,omitempty"`
	RecoveryResult     string             `json:"recovery_result,omitempty"`
	PolicyVersion      string             `json:"policy_version,omitempty"`
	FormulationVersion string             `json:"formulation_version,omitempty"`
	SubmittingOrg      string             `json:"submitting_org"`
	// CommittedBy and CommittedAt are set by the chaincode from the
	// transaction context, never from client input, so a client cannot
	// misattribute a record to another organisation.
	CommittedBy string `json:"committed_by"`
	CommittedAt string `json:"committed_at"`
	TxID        string `json:"tx_id"`
}

// CommitResult is returned to the client after a successful write.
type CommitResult struct {
	ProvenanceID string `json:"provenanceId"`
	TxID         string `json:"txId"`
	RecordHash   string `json:"recordHash"`
	CommittedAt  string `json:"committedAt"`
	CommittedBy  string `json:"committedBy"`
}

// VerifyResult is returned by VerifyEvidence.
type VerifyResult struct {
	ProvenanceID string `json:"provenanceId"`
	Valid        bool   `json:"valid"`
	Detail       string `json:"detail"`
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// validatePayload rejects anything that must not reach the ledger.
func validatePayload(raw string) (map[string]interface{}, error) {
	if len(raw) > maxRecordBytes {
		return nil, fmt.Errorf(
			"record is %d bytes, above the %d-byte limit; bulk data belongs off-chain",
			len(raw), maxRecordBytes)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("payload is not a JSON object: %v", err)
	}

	for key := range decoded {
		lowered := strings.ToLower(key)
		for _, forbidden := range forbiddenKeys {
			if lowered == forbidden {
				return nil, fmt.Errorf(
					"payload contains forbidden key %q; raw telemetry, evidence "+
						"bodies and patient context must stay off-chain and be "+
						"referenced by hash, because this ledger is replicated to "+
						"every organisation and is immutable", key)
			}
		}
	}

	if decoded["incident_id"] == nil || decoded["incident_id"] == "" {
		return nil, fmt.Errorf("payload must carry an incident_id")
	}
	return decoded, nil
}

// sha256Sum returns the SHA-256 digest of b.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// recordHash is the deterministic digest the client can independently
// recompute from the same payload.
//
// NOTE ON CANONICALISATION: Go's encoding/json sorts map keys, and the
// Python client uses json.dumps(sort_keys=True, separators=(",", ":")).
// Both therefore produce the same byte sequence for the same object, so
// the client can recompute this digest and compare. If either side changes
// its serialisation, this correspondence must be re-verified - a silent
// divergence would make every evidence check fail for the wrong reason.
func recordHash(payload map[string]interface{}) string {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256Sum(canonical))
}

// ---------------------------------------------------------------------------
// Write transactions
// ---------------------------------------------------------------------------

func (c *ProvenanceContract) commit(
	ctx contractapi.TransactionContextInterface,
	provenanceID string,
	raw string,
	expectedEventType string,
) (*CommitResult, error) {
	if provenanceID == "" {
		return nil, fmt.Errorf("provenanceID must not be empty")
	}

	// Append-only: refuse to overwrite. An incident's history must not be
	// rewritable after the fact.
	existing, err := ctx.GetStub().GetState(provenanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read world state: %v", err)
	}
	if existing != nil {
		return nil, fmt.Errorf(
			"provenance id %s is already committed; this ledger is append-only",
			provenanceID)
	}

	payload, err := validatePayload(raw)
	if err != nil {
		return nil, err
	}

	eventType, _ := payload["event_type"].(string)
	if expectedEventType != "" && eventType != expectedEventType {
		return nil, fmt.Errorf(
			"payload event_type %q does not match the transaction invoked (%q)",
			eventType, expectedEventType)
	}

	clientOrg, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("could not determine submitting organisation: %v", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return nil, fmt.Errorf("could not read transaction timestamp: %v", err)
	}
	committedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).
		UTC().Format(time.RFC3339Nano)

	// Attribution and time come from the transaction context, never from
	// client input.
	payload["committed_by"] = clientOrg
	payload["committed_at"] = committedAt
	payload["tx_id"] = ctx.GetStub().GetTxID()

	stored, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("could not serialise record: %v", err)
	}
	if err := ctx.GetStub().PutState(provenanceID, stored); err != nil {
		return nil, fmt.Errorf("could not write record: %v", err)
	}

	// Composite key for history queries by incident.
	incidentID, _ := payload["incident_id"].(string)
	indexKey, err := ctx.GetStub().CreateCompositeKey(
		"incident~provenance", []string{incidentID, provenanceID})
	if err != nil {
		return nil, fmt.Errorf("could not create index key: %v", err)
	}
	if err := ctx.GetStub().PutState(indexKey, []byte{0}); err != nil {
		return nil, fmt.Errorf("could not write index: %v", err)
	}

	// Emit an event so subscribers (the SOC dashboard) see commits live.
	if err := ctx.GetStub().SetEvent(eventType, stored); err != nil {
		return nil, fmt.Errorf("could not emit event: %v", err)
	}

	return &CommitResult{
		ProvenanceID: provenanceID,
		TxID:         ctx.GetStub().GetTxID(),
		RecordHash:   recordHash(payload),
		CommittedAt:  committedAt,
		CommittedBy:  clientOrg,
	}, nil
}

// RecordIncident commits that an incident was opened.
func (c *ProvenanceContract) RecordIncident(
	ctx contractapi.TransactionContextInterface, provenanceID string, payload string,
) (*CommitResult, error) {
	return c.commit(ctx, provenanceID, payload, "incident_recorded")
}

// RecordDecision commits the patient-aware decision and its counterfactual.
func (c *ProvenanceContract) RecordDecision(
	ctx contractapi.TransactionContextInterface, provenanceID string, payload string,
) (*CommitResult, error) {
	return c.commit(ctx, provenanceID, payload, "decision_recorded")
}

// RecordApproval commits a human approval decision.
func (c *ProvenanceContract) RecordApproval(
	ctx contractapi.TransactionContextInterface, provenanceID string, payload string,
) (*CommitResult, error) {
	return c.commit(ctx, provenanceID, payload, "approval_recorded")
}

// RecordResponse commits an executed response and its policy verdict.
func (c *ProvenanceContract) RecordResponse(
	ctx contractapi.TransactionContextInterface, provenanceID string, payload string,
) (*CommitResult, error) {
	return c.commit(ctx, provenanceID, payload, "response_recorded")
}

// RecordRecovery commits the recovery verification outcome.
func (c *ProvenanceContract) RecordRecovery(
	ctx contractapi.TransactionContextInterface, provenanceID string, payload string,
) (*CommitResult, error) {
	return c.commit(ctx, provenanceID, payload, "recovery_recorded")
}

// ---------------------------------------------------------------------------
// Read transactions
// ---------------------------------------------------------------------------

// GetProvenance returns one committed record.
func (c *ProvenanceContract) GetProvenance(
	ctx contractapi.TransactionContextInterface, provenanceID string,
) (map[string]interface{}, error) {
	stored, err := ctx.GetStub().GetState(provenanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read world state: %v", err)
	}
	if stored == nil {
		return nil, fmt.Errorf("provenance id %s does not exist", provenanceID)
	}
	var record map[string]interface{}
	if err := json.Unmarshal(stored, &record); err != nil {
		return nil, fmt.Errorf("stored record is malformed: %v", err)
	}
	return record, nil
}

// GetIncidentHistory returns every committed record for one incident.
func (c *ProvenanceContract) GetIncidentHistory(
	ctx contractapi.TransactionContextInterface, incidentID string,
) ([]map[string]interface{}, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(
		"incident~provenance", []string{incidentID})
	if err != nil {
		return nil, fmt.Errorf("failed to query index: %v", err)
	}
	defer iterator.Close()

	records := []map[string]interface{}{}
	for iterator.HasNext() {
		entry, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate index: %v", err)
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(entry.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		record, err := c.GetProvenance(ctx, parts[1])
		if err != nil {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// VerifyEvidence checks a claimed evidence hash against the committed one.
//
// Returns Valid=false for a missing record rather than an error, so a
// caller cannot read "record not found" as a pass.
func (c *ProvenanceContract) VerifyEvidence(
	ctx contractapi.TransactionContextInterface, provenanceID string, evidenceHash string,
) (*VerifyResult, error) {
	record, err := c.GetProvenance(ctx, provenanceID)
	if err != nil {
		return &VerifyResult{
			ProvenanceID: provenanceID,
			Valid:        false,
			Detail:       "no such provenance record",
		}, nil
	}
	committed, _ := record["evidence_hash"].(string)
	if committed == "" {
		return &VerifyResult{
			ProvenanceID: provenanceID,
			Valid:        false,
			Detail:       "record carries no evidence hash",
		}, nil
	}
	if committed != evidenceHash {
		return &VerifyResult{
			ProvenanceID: provenanceID,
			Valid:        false,
			Detail: fmt.Sprintf(
				"evidence hash mismatch: committed %s, presented %s",
				committed, evidenceHash),
		}, nil
	}
	return &VerifyResult{
		ProvenanceID: provenanceID,
		Valid:        true,
		Detail:       "evidence hash matches the committed record",
	}, nil
}

// GetChainInfo reports the ledger height for the client's verify_chain.
func (c *ProvenanceContract) GetChainInfo(
	ctx contractapi.TransactionContextInterface,
) (map[string]interface{}, error) {
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to range over world state: %v", err)
	}
	defer iterator.Close()

	count := 0
	for iterator.HasNext() {
		if _, err := iterator.Next(); err != nil {
			break
		}
		count++
	}
	return map[string]interface{}{
		"height":  count,
		"channel": ctx.GetStub().GetChannelID(),
	}, nil
}

func unusedMain() {
	chaincode, err := contractapi.NewChaincode(&ProvenanceContract{})
	if err != nil {
		panic(fmt.Sprintf("could not create provenance chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("could not start provenance chaincode: %v", err))
	}
}
