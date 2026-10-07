# policy_engine

L6 of the architecture. The deterministic, authoritative safety/policy layer — no
LLM call anywhere in this package. Decides autonomous-execution-allowed vs.
conditional-autonomy vs. human-approval-required from a `RiskScore` and
`ProposedResponse`. This is the layer agents must never be able to bypass; the rule
table lives here as explicit, reviewable code.

Status: not started. Phase 6 work.
