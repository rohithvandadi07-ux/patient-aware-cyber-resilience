# risk_engine

L5 of the architecture. The patient-aware dual-risk engine behind a pluggable
`RiskModel` interface. `RuleBasedRiskModel` (v0) is an explicit, documented,
auditable rule table — not a trained model. The actual mathematical form of
`Decision = f(cyber_risk, clinical_risk, response_impact)` is an open research
question, deliberately not committed to in this interface.

Status: Phase 5 complete.
- `model.py`: the `RiskModel` Protocol (Section 12). Also documents a schema
  note worth knowing before touching this package: `RiskScore.response_impact`
  is typed `dict[str, ImpactLevel]` in the real Pydantic schema, not
  `dict[action_id, float]` as Section 12's prose literally says — built
  against the real, already-shipped schema that Phase 4's agents depend on.
- `rules.py`: named, independently-testable rule functions —
  `score_cyber_risk` (severity + confidence), `score_clinical_risk`
  (criticality + clinical impact + a patient-dependency floor), and
  `score_response_impact` (per-action-category impact, implementing Section
  12's literal example rule and extending it to every `ResponseActionCategory`).
- `rule_based.py`: `RuleBasedRiskModel`, thin wiring over `rules.py` into one
  `RiskModel`-conforming object with a real (non-templated) `explanation`
  naming every rule that fired.
- `tests/test_scenarios.py`: Section 17's Scenario A and B, exercised at the
  risk-engine level (the Policy Engine/Orchestrator/blockchain layers those
  scenarios also describe don't exist yet — Phase 6-8). Scenario B's
  "never autonomously shuts down a patient-dependent, high-criticality
  device" assertion is covered across varying severity and confidence levels.

Verified: 53 tests passing, 100% branch coverage (measured with `coverage.py`,
not assumed) across `model.py`/`rules.py`/`rule_based.py`.
