package main

import (
	"ccverify/contractapi"
	"encoding/json"
	"fmt"
	"strings"
)

type stub struct {
	state  map[string][]byte
	events map[string][]byte
}

func (s *stub) GetState(k string) ([]byte, error) { return s.state[k], nil }
func (s *stub) PutState(k string, v []byte) error { s.state[k] = v; return nil }
func (s *stub) GetTxID() string                   { return "tx-abc123" }
func (s *stub) GetChannelID() string              { return "pacrchannel" }
func (s *stub) GetTxTimestamp() (*contractapi.Timestamp, error) {
	return &contractapi.Timestamp{Seconds: 1767254400, Nanos: 0}, nil
}
func (s *stub) CreateCompositeKey(p string, a []string) (string, error) {
	return p + "\x00" + strings.Join(a, "\x00"), nil
}
func (s *stub) SplitCompositeKey(k string) (string, []string, error) {
	parts := strings.Split(k, "\x00")
	return parts[0], parts[1:], nil
}

type iter struct {
	items []*contractapi.KV
	i     int
}

func (it *iter) HasNext() bool                  { return it.i < len(it.items) }
func (it *iter) Next() (*contractapi.KV, error) { v := it.items[it.i]; it.i++; return v, nil }
func (it *iter) Close() error                   { return nil }
func (s *stub) GetStateByPartialCompositeKey(p string, a []string) (contractapi.StateQueryIteratorInterface, error) {
	prefix := p + "\x00" + strings.Join(a, "\x00")
	out := []*contractapi.KV{}
	for k := range s.state {
		if strings.HasPrefix(k, prefix) && strings.Contains(k, "\x00") {
			out = append(out, &contractapi.KV{Key: k})
		}
	}
	return &iter{items: out}, nil
}
func (s *stub) GetStateByRange(a, b string) (contractapi.StateQueryIteratorInterface, error) {
	out := []*contractapi.KV{}
	for k, v := range s.state {
		if !strings.Contains(k, "\x00") {
			out = append(out, &contractapi.KV{Key: k, Value: v})
		}
	}
	return &iter{items: out}, nil
}
func (s *stub) SetEvent(n string, p []byte) error { s.events[n] = p; return nil }

type ident struct{}

func (ident) GetMSPID() (string, error) { return "SecurityOpsMSP", nil }

type ctx struct{ s *stub }

func (c *ctx) GetStub() contractapi.ChaincodeStubInterface            { return c.s }
func (c *ctx) GetClientIdentity() contractapi.ClientIdentityInterface { return ident{} }

func main() {
	c := &ProvenanceContract{}
	tc := &ctx{s: &stub{state: map[string][]byte{}, events: map[string][]byte{}}}
	ok, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			ok++
			fmt.Printf("  PASS %s\n", name)
		} else {
			fail++
			fmt.Printf("  FAIL %s: %s\n", name, detail)
		}
	}
	fmt.Println("=== chaincode logic verification ===")

	good := `{"provenance_id":"PRV-000001","event_type":"incident_recorded","incident_id":"INC-000001","device_id":"VENT-1","timestamp":"2026-01-01T08:00:00Z","evidence_hash":"abc123","submitting_org":"SecurityOpsMSP"}`
	r, err := c.RecordIncident(tc, "PRV-000001", good)
	check("valid incident commits", err == nil && r != nil, fmt.Sprint(err))
	if r != nil {
		check("tx id from context", r.TxID == "tx-abc123", r.TxID)
		check("org from context not client input", r.CommittedBy == "SecurityOpsMSP", r.CommittedBy)
		check("record hash computed", len(r.RecordHash) == 64, r.RecordHash)
	}

	_, err = c.RecordIncident(tc, "PRV-000001", good)
	check("append-only: rewrite refused", err != nil && strings.Contains(err.Error(), "append-only"), fmt.Sprint(err))

	bad := `{"event_type":"incident_recorded","incident_id":"INC-2","patient":{"ref":"SYN-PT-1"}}`
	_, err = c.RecordIncident(tc, "PRV-000002", bad)
	check("patient data rejected", err != nil && strings.Contains(err.Error(), "forbidden key"), fmt.Sprint(err))

	big := `{"event_type":"incident_recorded","incident_id":"INC-3","notes":"` + strings.Repeat("x", 5000) + `"}`
	_, err = c.RecordIncident(tc, "PRV-000003", big)
	check("oversized record rejected", err != nil && strings.Contains(err.Error(), "limit"), fmt.Sprint(err))

	noinc := `{"event_type":"incident_recorded"}`
	_, err = c.RecordIncident(tc, "PRV-000004", noinc)
	check("missing incident_id rejected", err != nil, fmt.Sprint(err))

	mism := `{"event_type":"decision_recorded","incident_id":"INC-5"}`
	_, err = c.RecordIncident(tc, "PRV-000005", mism)
	check("event_type mismatch rejected", err != nil && strings.Contains(err.Error(), "does not match"), fmt.Sprint(err))

	v, _ := c.VerifyEvidence(tc, "PRV-000001", "abc123")
	check("evidence verify: match", v.Valid, v.Detail)
	v, _ = c.VerifyEvidence(tc, "PRV-000001", "wronghash")
	check("evidence verify: mismatch", !v.Valid && strings.Contains(v.Detail, "mismatch"), v.Detail)
	v, _ = c.VerifyEvidence(tc, "PRV-NOPE", "abc123")
	check("missing record is NOT a pass", !v.Valid, v.Detail)

	hist, err := c.GetIncidentHistory(tc, "INC-000001")
	check("history by incident", err == nil && len(hist) == 1, fmt.Sprintf("%d records, %v", len(hist), err))

	info, err := c.GetChainInfo(tc)
	check("chain info", err == nil && info["channel"] == "pacrchannel", fmt.Sprint(info))

	rec, err := c.GetProvenance(tc, "PRV-000001")
	check("get provenance", err == nil && rec["incident_id"] == "INC-000001", fmt.Sprint(err))

	stored, _ := json.Marshal(rec)
	check("stored record carries no patient key", !strings.Contains(string(stored), "patient"), string(stored)[:60])

	fmt.Printf("\n%d passed, %d failed\n", ok, fail)
	if fail > 0 {
		panic("chaincode verification failed")
	}
}
