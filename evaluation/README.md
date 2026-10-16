# evaluation

Metric computation and report generation for the research evaluation described in
architecture spec Section 18 — cybersecurity metrics (precision, recall, F1, FPR,
latency), agentic AI metrics, patient-safety metrics (unsafe-response rate,
unnecessary-isolation rate), resilience metrics (MTTD, MTTR), and blockchain metrics.

Status: Phase 13 complete and extended beyond its own gate — the
detection-only vs. full-system baseline comparison Section 19's Phase 13
gate requires is real and reported here, and so is the fuller patient-safety
comparison Section 18 describes: all five named systems and all six
"without-X" ablations, not just the one pair the gate names. The actual
computation code lives in `backend/app/evaluation/` (see that package's
README for what's real code versus a disclosed stand-in); this directory
holds the reports it produces:

- `phase13_baseline_comparison.md` / `.json` — all five systems
  (`detection_only`, `fixed_response`, `detection_plus_agentic_ai`,
  `detection_plus_risk_engine`, `full_system`) and all six ablations
  (`without_healthcare_context`, `without_clinical_criticality`,
  `without_response_impact_assessment`, `without_agentic_ai`,
  `without_blockchain`, `without_recovery_verification`) compared across
  2038 randomized trials per detector (Random Forest and XGBoost),
  measuring `unsafe_autonomous_action_rate`, `unnecessary_isolation_rate`,
  and (for every ablation) an exhaustive count of trials where its decision
  differs from `full_system`'s. Headline results: the naive `fixed_response`
  baseline *and* `detection_plus_risk_engine` (the real Risk/Policy Engine,
  fed a fixed stub clinical context instead of the trial's real one) both
  autonomously execute a disruptive action on 100% (162/162) of high-stakes
  real attacks (a HIGH-criticality, patient-dependent device actually under
  attack); `detection_plus_agentic_ai` and `full_system` do so on 0%
  (0/162), routing every one to human approval instead — Section 17's
  Scenario B finding, generalized from two fixed scenarios to hundreds of
  randomized ones, and now showing the same safety property fails the
  instant the risk engine is fed the wrong context, even though the engine
  itself is unchanged. `unnecessary_isolation_rate` could not be measured
  this run (see the report for why — a disclosed dataset limitation, not a
  hidden gap); the same limitation, plus `full_system` never autonomously
  executing on a high-stakes real attack, is also why
  `without_recovery_verification`'s own metric (`would_reopen_if_verified`)
  reads 0% — disclosed and explained in the report, not hidden.

Still not started: the other three metric families Section 18 names
(resilience/MTTD/MTTR, blockchain-specific metrics, and latency) and the
agentic-AI-specific metrics beyond the `detection_plus_agentic_ai` system
comparison above. `without_blockchain` and `without_recovery_verification`
are implemented as real, runnable variants with an honestly-reported "zero
functional effect in this harness" finding, not fabricated differences —
see `backend/app/evaluation/baseline_systems.py`'s module docstring for
exactly why (neither component is part of this decision-path harness at
all: blockchain provenance recording and recovery's post-execution
device/network re-check both happen outside the single-trial decision step
this harness measures). Built as each becomes measurable against a real,
implemented component — never stubbed with placeholder numbers.

## Real-data detection baselines

- `ciciomt2024_results.md` / `.json` — XGBoost and Random Forest trained on the
  real CICIoMT2024 WiFi+MQTT train split and scored on the entire official test
  split, with 19-class, 6-family and binary (attack vs benign) views. Unlike the
  synthetic stand-in, this run has real benign false positives, so the
  `unnecessary_isolation_rate` inputs now exist; the Phase 13 harness has not yet
  been re-run on this data.
