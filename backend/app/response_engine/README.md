# response_engine

L7 of the architecture. The Response Orchestrator — the only service in the system
that executes a response action, and only the action the Policy Engine has cleared
(autonomously, or via a human approval written back to L6 first). Calls the
simulator's own command interface; never touches real infrastructure (there is
none — it's simulated).

Status: Phase 6 complete.
- `orchestrator.py`: `ResponseOrchestrator.execute(policy_decision, approval=None)`.
  Approval gating (`_check_approval_gate`) is checked before anything else:
  autonomous actions execute immediately (`executed_by="system"`);
  human-approval-required actions raise `ApprovalRequiredError` with no
  approval, `ValueError` on an incident-id mismatch between the approval and
  the decision, `ResponseRejectedError` on an explicit rejection, and only
  execute (with `executed_by=approval.approver_identity`) on a matching
  `APPROVED` record.
- **Honest execution scope**, following the project's stub-rather-than-fabricate
  pattern (same as `training.py`'s `load_real_dataset` and Phase 4's original
  `evaluate_policy` stub): the simulator only has a real mechanism for network
  isolation, power-off, and resetting to normal operation.
  - `SHUTDOWN` → `SimulatedDevice.power_off()` (added in Phase 6 alongside the
    new `OperationalState.OFF`; distinct from isolation — `network_state`
    becomes `"offline"`, not `"isolated"`).
  - `BLOCK_TRAFFIC`, `RESTRICT_COMMUNICATION`, `ISOLATE_NON_CRITICAL`,
    `ISOLATE_CRITICAL`, `QUARANTINE_SEGMENT` → `SimulatedDevice.isolate()`. All
    five collapse to the same observable simulator effect because the
    simulator has no network-topology model granular enough to distinguish
    them — documented in the module docstring, not silently collapsed.
  - `RESTART_SERVICE` → reset to `OperationalState.IDLE` / `network_state
    "connected"`.
  - `REVOKE_SESSION`, `ROTATE_CREDENTIALS`, `ACTIVATE_BACKUP`, `FAILOVER` → raise
    `NotImplementedError` naming the missing mechanism. No session,
    credential, backup, or failover concept exists anywhere in
    `app/iomt_simulator/device.py` — faking one here would mean these
    "execute" against nothing real.
  - A module-level exhaustiveness assertion (same pattern as
    `risk_engine/rules.py`'s disruption-tier check) guarantees every
    `ResponseActionCategory` is classified into exactly one of the groups
    above.
- `tests/test_orchestrator.py`: approval-required blocking (no approval,
  rejected approval, mismatched incident_id), autonomous execution bypassing
  approval entirely, unknown-incident/unknown-device propagation
  (`IncidentNotFoundError`/`DeviceNotFoundError`), correct device-state
  mutation for every supported action category, and `NotImplementedError` for
  every unsupported one.

Verified: 19 tests passing, 100% branch coverage (measured with `coverage.py`,
not assumed) across `orchestrator.py`.
