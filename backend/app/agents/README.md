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

**Post-Phase-15 update (closes the two gaps this section used to name):**

- **A real orchestration layer now exists**: `app/orchestration/
  orchestrator.py`'s `IncidentOrchestrator` sequences the five agents and
  the L5-L8 deterministic services automatically, over a real API endpoint
  (`POST /incidents/{id}/investigate`) -- the same sequence
  `tests/test_lifecycle_integration.py` already proved by hand, now run for
  real, including a real re-investigation loop when recovery verification
  reports `reinvestigation_required=True` (previously a dead-end status
  flag -- see `app/recovery/engine.py`'s module docstring and `claude/
  architecture-decisions.md`'s Post-Phase-15 gap audit).
- **A real LLM backend now exists**: `GeminiLLMClient`
  (`app/agents/llm_client.py`), wired to Google's Gemini API via the
  `google-genai` SDK. `MockLLMClient` is still the *default*
  (`Settings.llm_backend="mock"`) and still what every pre-existing agent
  unit test and `test_lifecycle_integration.py` use -- disclosed plainly in
  those tests' own docstrings, never presented as live model output.
  `llm_backend="gemini"` with a real `GEMINI_API_KEY` configured is what
  actually makes a live call; without a key, `_register_state` falls back
  to mock with a logged warning rather than constructing a client that
  would fail on its first use.
