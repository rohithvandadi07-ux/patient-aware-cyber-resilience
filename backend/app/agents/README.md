# agents

L4 of the architecture. The five agents — Investigation, Threat Reasoning, Healthcare
Context, Response Planning, Recovery Verification — each with its own input/output
schema, a read-only tool allowlist (`tools.py`'s `AgentToolkit`), and a persisted trace
record per call (`app/repositories/agent_traces.py`). None of these agents hold an
execute capability; only the Response Orchestrator (L7, Phase 6/7) will.

Status: Phase 4 complete. All five agents implemented and unit-tested against
`MockLLMClient` (no real LLM backend wired yet — that's an explicitly deferred
decision per the architecture doc's Section 11). `llm_client.py` holds the
`LLMClient` interface and the schema-validated retry-once-then-fail policy;
`base.py` holds the shared run/trace/stall scaffolding every agent calls through.

Known gaps carried forward on purpose, not fabricated around:
- `evaluate_policy` (Response Planning Agent's tool) raises `NotImplementedError`
  — the real Policy Engine is Phase 6 work with its own dedicated test suite.
- `plan_response` accepts `risk_score: RiskScore | None` — the Risk Engine that
  produces a real one is Phase 5 work; `None` is handled explicitly, never
  faked as zero risk.
- No orchestration layer sequences the five agents automatically yet (Section
  11: "the orchestration mechanism [...] is a Phase 4 decision, made after the
  schemas above are implemented and testable" — the schemas are now proven
  end-to-end via a manual chain in testing, but a real orchestrator is still
  open work for whichever phase wires the full incident lifecycle).
