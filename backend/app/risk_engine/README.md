# risk_engine

L5 of the architecture. The patient-aware dual-risk engine behind a pluggable
`RiskModel` interface. `RuleBasedRiskModel` (v0) is an explicit, documented,
auditable rule table — not a trained model. The actual mathematical form of
`Decision = f(cyber_risk, clinical_risk, response_impact)` is an open research
question, deliberately not committed to in this interface.

Status: not started. Phase 5 work.
