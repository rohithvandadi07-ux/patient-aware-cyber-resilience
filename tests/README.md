# tests

Integration and end-to-end tests — cross-module paths (e.g. detection through
incident creation) and the two deterministic scenarios from the architecture
specification, Section 17 (Scenario A: non-critical device compromised; Scenario B:
patient-dependent ventilator compromised). Unit tests for a single module live
beside that module instead (e.g. `backend/app/risk_engine/tests/`).

Status: scaffolded (Phase 1) — test harness configured, no scenario tests yet since
the components they exercise don't exist until later phases.
