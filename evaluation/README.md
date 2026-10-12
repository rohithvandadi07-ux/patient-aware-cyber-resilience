# evaluation

Metric computation and report generation for the research evaluation described in
architecture spec Section 18 — cybersecurity metrics (precision, recall, F1, FPR,
latency), agentic AI metrics, patient-safety metrics (unsafe-response rate,
unnecessary-isolation rate), resilience metrics (MTTD, MTTR), and blockchain metrics.

Status: Phase 13 partial — the detection-only vs. full-system baseline
comparison Section 19's Phase 13 gate requires is real and reported here.
The actual computation code lives in `backend/app/evaluation/` (see that
package's README for what's real code versus a disclosed stand-in); this
directory holds the reports it produces:

- `phase13_baseline_comparison.md` / `.json` — detection-only,
  fixed-response, and full-system compared across 2038 randomized trials
  per detector (Random Forest and XGBoost), measuring
  `unsafe_autonomous_action_rate` and `unnecessary_isolation_rate`. Headline
  result: the naive `fixed_response` baseline autonomously executes a
  disruptive action on 100% (162/162) of high-stakes real attacks (a
  HIGH-criticality, patient-dependent device actually under attack); the
  real Risk Engine + Policy Engine (`full_system`) does so on 0% (0/162),
  routing every one to human approval instead — Section 17's Scenario B
  finding, generalized from two fixed scenarios to hundreds of randomized
  ones. `unnecessary_isolation_rate` could not be measured this run (see
  the report for why — a disclosed dataset limitation, not a hidden gap).

Still not started: the remaining four metric families (agentic AI,
resilience/MTTD/MTTR, blockchain, and latency), and the fuller
five-system/seven-ablation comparison Section 18 describes beyond the one
pair the Phase 13 gate names. Built as each becomes measurable against a
real, implemented component — never stubbed with placeholder numbers.
