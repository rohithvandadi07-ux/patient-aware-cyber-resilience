# tests

Integration and end-to-end tests — cross-module paths (e.g. detection through
incident creation) and the two deterministic scenarios from the architecture
specification, Section 17 (Scenario A: non-critical device compromised; Scenario B:
patient-dependent ventilator compromised). Unit tests for a single module live
beside that module instead (e.g. `backend/app/risk_engine/tests/`).

## Status: Phase 11 complete — Scenario A and B run through the real UI

Section 19's Phase 11 gate, verbatim: "Scenario A and B run through the real
UI, not just backend tests." `e2e/test_scenario_a_e2e.py` and
`e2e/test_scenario_b_e2e.py` are that gate, exercised for real: a real
`uvicorn`-served backend and a real Vite dev-server frontend, both started as
actual processes (`e2e/conftest.py`), driven by a real Chromium browser via
Playwright (`pytest-playwright`) — not `TestClient`, not jsdom.

**What "runs through the real UI" means here, precisely:** every step that
has a button to click in the SOC dashboard is driven by a real Playwright
click against the real rendered page — assessing risk, proposing a response,
executing it (including, for Scenario B, filling in and submitting the real
human-approval form), submitting the recovery result, and draining the
blockchain outbox. The one step with no UI control to click is seeding the
incident's agent traces, because by design no such control exists anywhere
in this project yet (no live LLM backend, no orchestrator — see
`backend/app/agents/README.md`); `e2e/_seed_scenario.py` seeds those the same
disclosed way `backend/tests/test_lifecycle_integration.py` already does
(calling the five real agent functions directly, scripted via
`MockLLMClient`, never presented as live model output). Every assertion is
checked twice: once against the real rendered DOM, and once against the real
backend's JSON, so a UI-only assertion can never paper over a backend that
didn't actually do the thing.

**Scenario B's "safer non-shutdown action" is `isolate_non_critical`, chosen
by reading the real code, not by assumption** — see
`e2e/test_scenario_b_e2e.py`'s module docstring for the exact rule chain
(`app/risk_engine/rules.py::score_response_impact` scores it `HIGH`, not the
forced `CRITICAL` that `shutdown`/`isolate_critical` get on this device;
`app/policy_engine/rules.py::classify_routing` still routes `HIGH` impact to
`RULE_APPROVAL_HIGH_IMPACT`, so it stays approval-gated; and
`app/response_engine/orchestrator.py` can actually execute it, unlike
`rotate_credentials`). The test asserts all of this for real: the approval
form genuinely appears, a real human-shaped approval is submitted through
it, and the action that actually executes afterward is `isolate_non_critical`
— never `shutdown`, "regardless of attack severity," exactly as Section 17
requires.

Scenario A's incident is seeded through the real, pre-existing
`POST /incidents` endpoint (Phase 9); Scenario B's through the real, fixed
`POST /detections/run-scenario` endpoint (Phase 3/9) it's already shaped
for. Neither test adds a new scenario-triggering endpoint —
`backend/app/api/detections.py`'s own docstring already warns against that
as an unplanned feature, and neither scenario needs one.

Run it: `cd backend && .venv/bin/python -m pytest -c ../tests/pytest.ini ../tests/e2e`
(or, since `tests/pytest.ini` sets `pythonpath`/`testpaths` for this
directory, simply `pytest` from inside `tests/` with that same interpreter).
Needs `playwright`/`pytest-playwright` installed (see
`backend/requirements-dev.txt`) and a Chromium build Playwright can find
(`playwright install chromium`, unless `PLAYWRIGHT_BROWSERS_PATH` already
points at one). Not yet wired into `.github/workflows/ci.yml` — that CI job
only runs `backend/`'s own suite; adding a browser-dependent, two-process
E2E job to CI is a deliberately separate decision from writing the suite
itself, left open rather than invented here.
