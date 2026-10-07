# blockchain

L9 of the architecture. The Fabric client and the asynchronous outbox worker that
commits the six provenance event types (`recordIncident`, `recordDecision`,
`recordApproval`, `recordResponse`, `recordRecovery`, `verifyEvidence`) to the
Hyperledger Fabric `test-network`. Never sits on the response-execution hot path —
writes are queued and confirmed asynchronously.

Status: not started. Phase 8 work.
