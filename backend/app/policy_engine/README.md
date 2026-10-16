# policy_engine

L6 of the architecture. The deterministic, authoritative safety/policy layer — no
LLM call anywhere in this package. Decides autonomous-execution-allowed vs.
conditional-autonomy vs. human-approval-required from a `RiskScore` and a chosen
response action. This is the layer agents must never be able to bypass; the rule
table lives here as explicit, reviewable code.

Status: Phase 6 complete.
- `rules.py`: `classify_routing` implements Section 13's three stated rules
  verbatim, plus one documented, conservative gap-fill for the one combination
  Section 13's rules don't jointly cover (`response_impact == MEDIUM and
  patient_dependency == True` for an action outside `{SHUTDOWN,
  ISOLATE_CRITICAL}`) — flagged in both the module docstring and the rule's own
  `policy_rule_id`/rationale so it is never mistaken for literal spec text.
  Also: `get_response_impact_for_action` (a safe lookup that raises rather than
  silently defaulting) and `decide_routing` (a convenience wrapper over both).
- `engine.py`: `PolicyEngine`, thin wiring (same relationship as
  `risk_engine/rule_based.py` has to `risk_engine/rules.py`) into `PolicyDecision`
  objects, with `evaluate_action` (single pre-chosen action — what
  `AgentToolkit.evaluate_policy` calls) and `evaluate` (Section 13's literal
  `RiskScore` + `ProposedResponse` input shape, routing on
  `recommended_action`). Both validate incident-id consistency across the
  objects they're given, mirroring `RuleBasedRiskModel`'s own check.
- Wired into the agent layer (Phase 4's `AgentToolkit.evaluate_policy`, which
  used to raise `NotImplementedError`, and `response_planning.py`'s
  `_try_evaluate_policy`) — the Response Planning Agent's prompt now carries a
  real per-candidate-action Policy Engine pre-check when a `RiskScore` is
  available, and an honest "not available" note when it isn't.
- `tests/test_rules.py` + `tests/test_engine.py`: Section 17's Scenario A and B
  re-exercised at this layer (Scenario A: auto-approved isolation; Scenario B:
  forced human approval for shutdown on a patient-dependent, high-criticality
  device regardless of cyber severity — including the real `RuleBasedRiskModel`
  output, not a hand-picked `RiskScore`).

Verified: 33 tests passing, 100% branch coverage (measured with `coverage.py`,
not assumed) across `rules.py`/`engine.py`.

**Final-completion additions.**

- **Opt-in detector-confidence gate.** `PolicyEngine(min_autonomous_confidence=...)`
  (env: `POLICY_MIN_AUTONOMOUS_CONFIDENCE`, off by default) routes an otherwise
  autonomous decision to human approval when the detector's confidence is below
  the threshold (`approval_low_detector_confidence`), or when the gate is on and
  the confidence is unknown (`approval_unknown_detector_confidence`, fail-closed).
  It only ever converts autonomous to approval, so it cannot make any decision
  less safe. The threshold must be chosen on validation data, not on the test
  split; see `evaluation/calibrated_gating.md`.
- **Ranked alternatives.** `PolicyDecision.alternatives` lists the other scored
  candidate actions ranked by (approval needed, response impact, security
  benefit), each with its own rule id; candidates with no score are skipped. The
  dashboard's response panel renders them as an "Alternatives considered" table.
