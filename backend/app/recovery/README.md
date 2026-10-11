# recovery

L8 of the architecture. The deterministic service that closes the loop after a
response executes: takes the Recovery Verification Agent's (L4) finding, records
it as evidence, and either closes the incident or re-opens it at the Investigation
Agent (L4) rather than silently closing — Section 7 step 12 / Section 4's dashed
loop.

Status: Phase 7 complete.
- `engine.py`: `RecoveryOrchestrator.process_result(result: RecoveryResult) ->
  Incident`. Same relationship to the L4 Recovery Verification Agent
  (`app/agents/recovery_verification.py`) as the Policy Engine (L6) has to the
  Response Planning Agent: the agent produces a structured finding and
  deliberately does not act on it; this class is the separate, non-agentic,
  deterministic service that does. Routes on `reinvestigation_required` first
  (the agent's own stated authoritative "should this reopen" signal) —
  `True` → `IncidentStatus.REOPENED` regardless of `recovery_succeeded`;
  `False` + `recovery_succeeded=True` → `IncidentStatus.RESOLVED`; `False` +
  `recovery_succeeded=False` (a combination that contradicts the agent's own
  contract) raises `InconsistentRecoveryResultError` rather than guessing.
  Every `RecoveryResult` is recorded as evidence before routing is attempted,
  including on the error path.
- Evidence is real and queryable, not just asserted: `RecoveryResultRepository`
  (`app/repositories/recovery_results.py`) stores every check per incident, and
  `AgentToolkit.get_recovery_results_for_incident` (Phase 7 addition to
  `app/agents/tools.py`) reads it back through the same tool-allowlist boundary
  every other agent read goes through. **Honestly scoped:** no agent's prompt
  calls this yet — Section 11's agent table doesn't name it, and actually
  re-invoking the Investigation Agent on reopen is a decision for whichever
  later phase builds the real multi-agent orchestration pipeline (still
  undecided, per Section 11's own note). This phase makes the evidence real;
  it does not fabricate an auto-reinvestigation pipeline that doesn't exist.
- `tests/test_engine.py`: every routing branch (resolved, reopened — including
  the case where `recovery_succeeded=True` but `reinvestigation_required=True`
  also reopens), the inconsistent-result error (and that the evidence is still
  recorded when it's raised), and unknown-incident propagation with no
  evidence recorded for a nonexistent incident.

Verified: 7 tests passing (plus 4 for `RecoveryResultRepository` and 3 new ones
on `AgentToolkit`), 100% branch coverage (measured with `coverage.py`, not
assumed) across `engine.py` and `recovery_results.py`.
