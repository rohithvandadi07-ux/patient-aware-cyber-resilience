# agents

L4 of the architecture. The five agents — Investigation, Threat Reasoning, Healthcare
Context, Response Planning, Recovery Verification — each with its own input/output
schema, a read-only tool allowlist (`tools.py`'s `AgentToolkit`), and a persisted trace
record per call (`app/repositories/agent_traces.py`). None of these agents hold an
execute capability; only the Response Orchestrator (L7, Phase 6/7) will.

Status: Phase 4 complete (all five agents implemented and unit-tested against
`MockLLMClient` — no real LLM backend wired yet, an explicitly deferred
decision per the architecture doc's Section 11). `llm_client.py` holds the
`LLMClient` interface and the schema-validated retry-once-then-fail policy;
`base.py` holds the shared run/trace/stall scaffolding every agent calls
through. Two later phases wired real pieces in underneath this package without
changing any agent's own code: Phase 6 made `AgentToolkit.evaluate_policy`
real (see below), and Phase 7 added `AgentToolkit.get_recovery_results_for_incident`
(not yet called by any agent's prompt — exposed so recovery evidence is
genuinely queryable, not wiring a re-investigation pipeline that doesn't
decide to exist yet).

Known gaps carried forward on purpose, not fabricated around:
- `evaluate_policy` (Response Planning Agent's tool) now routes to the real
  Policy Engine (L6, Phase 6, `app/policy_engine/engine.py`) rather than
  raising `NotImplementedError` as it did through Phase 4/5 — but it is
  still read-only ("would this be auto-approved"), never execution.
- `plan_response` accepts `risk_score: RiskScore | None` — Phase 5's Risk
  Engine can now supply a real one, but the agent still handles `None`
  explicitly (no risk score available yet) rather than faking zero risk.
- No orchestration layer sequences the five agents automatically yet (Section
  11: "the orchestration mechanism [...] is a Phase 4 decision, made after the
  schemas above are implemented and testable" — the schemas are now proven
  end-to-end, including through the real HTTP API, by Phase 10's
  `backend/tests/test_lifecycle_integration.py`, which manually sequences the
  five agents exactly the way a real orchestrator eventually will. A real
  orchestrator is still open work for whichever phase decides to build one.
- No real LLM backend exists anywhere in this project (Phase 10's lifecycle
  integration test above, like every agent unit test, uses `MockLLMClient`
  with scripted responses — disclosed plainly in that test's own docstring,
  never presented as live model output).
