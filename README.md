# Patient-Aware Cyber Resilience

A research-grade, patient-aware autonomous cyber-resilience platform for healthcare
IoMT (Internet of Medical Things). Target environment: a simulated smart hospital
running an infusion pump, a ventilator, and an ECG/patient monitor.

The central research question: **how can an autonomous cyber-defense system
protect safety-critical healthcare IoMT devices while making response decisions
that jointly account for cybersecurity risk and patient/clinical impact?**

This is not a detection-only IDS, a chatbot, a blockchain logger, or a dashboard —
it is one closed-loop platform combining:

- **Cybersecurity detection** — what is happening (ML-based attack detection on
  real IoMT network-traffic datasets)
- **Agentic AI** — what should we do (five agents with structured I/O: investigate,
  reason about the threat, assess clinical context, plan a response, verify
  recovery)
- **A patient-aware dual-risk engine** — jointly weighing cyber risk against
  clinical criticality and response impact, so the most secure action is not
  assumed to be the safest one
- **A deterministic safety/policy layer** — the sole authority on whether a
  response executes autonomously or requires human approval; agents never bypass it
- **Permissioned blockchain provenance** (Hyperledger Fabric) — auditable,
  tamper-evident record of incidents, decisions, approvals, responses, and
  recovery, without ever storing raw patient data or logs on-chain
- **A healthcare SOC dashboard** — making the full incident lifecycle, and the
  patient-aware decision at its center, visible and explainable

## Status

This project was built in 16 phases (0–15); all 15 build phases are complete
as of this commit, locally (see the note on GitHub below). See
[`docs/architecture.md`](docs/architecture.md) Section 19 for the full phase
plan and gates, [`docs/phase15-verification.md`](docs/phase15-verification.md)
for the final pass checking every one of that document's claims against the
real, current code, and the Claude Project doc
`claude/architecture-decisions.md` for phase-by-phase decisions. "Complete"
means each phase's own literal gate was met, including by a disclosed
deviation where the sandbox or an earlier locked decision forced one
(Fabric's native bring-up, the synthetic stand-in dataset, Phase 14's
registry block) — not that every feature the original brief mentioned
anywhere exists; `docs/phase15-verification.md` and the "still not built"
bullet below are the honest account of what that excludes.

- **Phases 0–9 (architecture through backend integration): complete.** A
  three-device IoMT simulator with scripted attack scenarios; a trained
  baseline detector (Random Forest/XGBoost) against the synthetic stand-in
  dataset (`datasets/LICENSE_NOTES.md` — real CICIoMT2024 data has not been
  used); all five agents (`app/agents/`), schema-validated and unit-tested
  against `MockLLMClient` — no live LLM backend is wired in yet, a
  deliberate, still-open decision, not a gap this README hides; the
  rule-based dual-risk engine; the deterministic policy engine and response
  orchestrator; the recovery orchestrator; Hyperledger Fabric provenance
  (`test-network` + chaincode); and all 12 resource routers behind the
  FastAPI backend.
- **Phase 10 (SOC dashboard): complete.** `frontend/` is a real
  React/TypeScript/Vite dashboard where one incident's full lifecycle is
  viewable: detection status, a dual cyber-risk/clinical-risk panel (equal
  visual weight, per Section 16 — never cyber-risk-as-headline), real
  agent-activity data (or an honest "not run" state, never fabricated),
  evidence, the proposed/executed response (including a real
  human-approval flow when the policy engine requires one), recovery
  verification, and the blockchain audit trail.
  `backend/tests/test_lifecycle_integration.py` and
  `frontend/src/routes/IncidentDetail.fullLifecycle.test.tsx` each drive
  one real incident through this entire chain end to end and assert on
  the real result.
- **Phase 11 (end-to-end integration): complete.** `tests/e2e/` drives
  Scenario A (infusion-pump-01, DoS) and Scenario B (ventilator-01,
  command-injection/MITM) through the real rendered SOC dashboard in a real
  Chromium browser (Playwright), against a real running backend and
  frontend process — not `TestClient`, not jsdom. Scenario B's test is the
  most direct check of this project's central research claim: a real human
  approval, submitted through the real approval form, clears a genuinely
  safer non-shutdown action (`isolate_non_critical`, verified against the
  real Policy Engine and Risk Engine rule tables, not assumed) — the system
  never autonomously shuts down this patient-dependent, high-criticality
  device. See `tests/README.md` for exactly what "through the real UI"
  means here and what still has no UI control (agent-trace seeding, by
  design — no live LLM backend or orchestrator exists yet, unchanged by
  this phase).
- **Phase 12 (security hardening pass): complete.** The architecture spec's
  Phase 12 gate calls for verifying "the brief's Section 16" checklist
  item by item; the original brief's Section 16 is not recoverable in this
  repo, project, or session, so `docs/security-checklist.md` is an
  explicitly disclosed, self-constructed substitute (OWASP API Security Top
  10 2023, OWASP ASVS Level 1, CWE Top 25) rather than something fabricated
  and mislabeled as the brief's own text. Real findings were fixed, not
  just logged: `pip-audit` found 16 CVEs in the `fastapi`/`starlette`
  dependency chain and in `pytest` (fixed by bumping `fastapi` 0.115.6 →
  0.143.0 and `pytest`/`pytest-asyncio` to 9.0.3/1.4.0 — 0 vulnerabilities
  now), and `Settings.debug` now defaults to `False` instead of `True` (a
  security-relevant default should fail safe, not require an operator to
  remember to turn it off). Secrets scanning, subprocess/injection safety,
  error-disclosure surfaces, and Fabric's TLS posture were all re-verified
  against the real code, not re-asserted from memory. Known gaps (no rate
  limiting, no authentication layer) are disclosed, not fixed this phase —
  see the checklist for why. Full backend/frontend/E2E suites pass against
  the upgraded dependencies.
- **Phase 13 (experiments + evaluation): partial, gate met.** The Phase 13
  gate ("at least the detection-only vs. full-system baseline comparison
  has real, reported numbers") is met: `backend/app/evaluation/` runs all
  three of detection-only, a naive fixed-response baseline, and the real
  Risk Engine + Policy Engine (`full_system`) across 2038 randomized trials
  per detector (Random Forest and XGBoost), pairing each held-out test row
  with an independently-sampled device context. Real result (see
  `evaluation/phase13_baseline_comparison.md`): on the 162 trials per model
  that were both a real attack and a HIGH-criticality, patient-dependent
  device, the naive baseline autonomously executed a disruptive action
  100% of the time (162/162); the real patient-aware system did so 0% of
  the time (0/162), routing every one to human approval instead —
  Section 17's Scenario B finding, generalized from two fixed scenarios to
  hundreds of randomized ones. One metric (`unnecessary_isolation_rate`)
  could not be measured this run — a disclosed dataset limitation (the
  synthetic stand-in's classes are cleanly separated enough that both
  detectors measured zero false positives), not a hidden gap; see the
  report for why. The fuller five-system/seven-ablation comparison Section
  18 describes remains for later.
- **Phase 14 (Dockerization + deployment): written, config-validated, not
  run-verified here.** `docker-compose.yml` now brings up backend +
  frontend (served via nginx, not the Vite dev server) + Postgres in one
  `docker compose up` — Section 19's literal gate, for the three services
  this project controls. Hyperledger Fabric stays outside compose,
  deliberately: that's Phase 8's own locked decision (its native-binary
  bring-up, `blockchain/network/`, is unchanged), not something this
  phase overlooked. The honest limit on this phase: this project's
  development sandbox blocks every container registry tried (Docker Hub,
  ghcr.io, mcr.microsoft.com, gcr.io all returned 403 Forbidden — the same
  block Phase 8 found for Fabric, now confirmed for every other base image
  too, including the pre-existing `backend` Dockerfile's own
  `python:3.12-slim`), so nothing here has actually run `docker compose up`
  to completion anywhere in this project's history. `docker compose
  config` parses and interpolates the file cleanly, which needs no image
  pull; an actual build/run needs an environment with registry access. See
  the "Docker" section below for the full disclosure.
- **Phase 15 (final documentation pass): complete.** Section 19's literal
  gate — "every claim in `docs/` is checked against what's actually
  implemented and tested" — is met by `docs/phase15-verification.md`,
  which re-walks every checkable claim in `docs/architecture.md` (the
  frozen Phase 0 spec) against the real, current code, section by section,
  and names every place reality diverged from the original plan, including
  several never stated plainly inside `docs/` before this phase (the real
  `RiskScore.response_impact` schema vs. the spec's literal type; Fabric's
  native-binary bring-up vs. the spec's Docker Compose plan; the
  `infrastructure/` directory, found empty and corrected, since the real
  `docker-compose.yml`/Dockerfiles live elsewhere; and a sharper statement
  of exactly how inert the Postgres/TimescaleDB container is — real,
  healthy, but connected to by no application code at all). Full backend
  suite (359 tests), full frontend suite (46 tests), and the Phase 11 E2E
  suite (2/2) were all re-run for this phase, not carried forward by
  assertion.
- **Post-Phase-15, user-directed (not a numbered phase — all 16 planned
  phases finished at Phase 15 above): a real, scope-limited Postgres
  migration.** `incidents`, `agent_traces`, `recovery_results`,
  `proposed_responses`, `executed_responses`, and `outbox_entries`
  (`app/models/orm.py`) are now real tables, with a `Postgres*`
  implementation of each corresponding repository
  (`app/repositories/*.py`, `app/blockchain/outbox.py`) that a new
  `Settings.repository_backend` flag ("memory" default, "postgres" to use
  them) selects — `docker-compose.yml`'s backend service now sets it to
  "postgres", so Phase 14's previously-inert Postgres container is
  actually read from and written to when run that way. Verified for real
  against a local Postgres 16 instance (not Docker — this sandbox's
  registry block, unchanged since Phase 8/14 — natively installed and
  started instead): a new, real, Postgres-gated test suite
  (`backend/tests/test_postgres_repositories.py`, 7 tests, skipped rather
  than faked when no Postgres is reachable) genuinely passes, and the full
  pre-existing backend suite (356 tests, not 359 — the earlier figure was
  an approximation, not a regression) still passes unchanged against the
  default in-memory path, confirming zero behavior change for anyone not
  opting in. Deliberately NOT covered, same disclosure discipline as
  everything else here: `NetworkEventStore`/`TelemetryStore` (Section 8's
  separate TimescaleDB-hypertable category — at this point still
  in-memory; the final-completion pass below later added Postgres-backed
  stores for them); the IoMT simulator's `DeviceRegistry` (live
  simulation state, not a persisted catalog); a real migration tool
  (Alembic — `create_all` only); and an async rewrite (a sync driver,
  `psycopg`, was chosen instead so every existing `async def` route's
  unawaited call sites stay correct unchanged — see `app/core/db.py`'s
  docstring for the accepted, disclosed tradeoff). See
  `app/models/README.md` and `app/repositories/README.md` for the full
  detail.
- **Post-Phase-15, round two, user-directed: real orchestration, a real
  LLM backend, authentication, the fuller ablation set, 4 more SOC
  dashboard views, and 5 standalone docs.** Closes most of what the
  previous bullet's "still not built" list named:
  - **A real multi-agent orchestrator** (`app/orchestration/
    orchestrator.py`'s `IncidentOrchestrator`) now sequences the five
    agents and the L5-L8 deterministic services automatically, over a new
    `POST /incidents/{id}/investigate` endpoint — the same sequence
    `tests/test_lifecycle_integration.py` already proved by hand, now run
    for real, including a genuine re-investigation loop when recovery
    verification reports `reinvestigation_required=True` (previously a
    dead-end `REOPENED` status flag nothing re-triggered — a real,
    previously-disclosed gap, now closed and covered by 4 new tests in
    `app/orchestration/tests/test_orchestrator.py`, including the bounded
    re-investigation budget).
  - **A real LLM backend**: `GeminiLLMClient` (`app/agents/llm_client.py`,
    Google's Gemini API via the `google-genai` SDK), selected via
    `Settings.llm_backend="gemini"` with a `GEMINI_API_KEY` configured.
    Defaults to `"mock"` (`MockLLMClient`, unchanged), so every
    pre-existing test is unaffected; falls back to mock with a logged
    warning if `"gemini"` is requested with no key, rather than
    constructing a client that would fail on first use. 10 new offline
    tests (`google.genai.Client` mocked out, no real network call) prove
    the wiring; an actual live Gemini call has not been made in this
    sandbox (no key was available here) — that is still open until a real
    `GEMINI_API_KEY` is configured and exercised.
  - **Authentication/authorization** (`app/core/auth.py`): real,
    API-key-based, three ranked roles (`viewer` < `operator` < `approver`),
    wired onto every route except `/health`. Defaults to
    `Settings.auth_enabled=False` (this app's historical no-auth
    behavior, now represented explicitly rather than having no concept of
    a principal at all); enabling it with no keys configured fails closed.
    Approving/executing a response and auto-approving an investigation
    cycle require the `approver` role once enabled. 10 new tests.
  - **The ablation/baseline set grew from 3 to 11 real, measured arms**:
    `SystemName` now has all 5 the master plan names (added
    `detection_plus_agentic_ai`, `detection_plus_risk_engine`); all 6
    "without-X" ablations are real and runnable, with two (`without_
    blockchain`, `without_recovery_verification`) honestly confirmed —
    programmatically, not asserted — to have zero effect on this harness's
    decision path, since neither component sits on it. See
    `evaluation/README.md` for the full, still-current disclosure of what
    remains unmeasured (the real five-system/seven-ablation study still
    needs the real benchmark dataset below, not just more code).
  - **4 more SOC dashboard views** (`frontend/src/routes/{Overview,Fleet,
    ThreatMonitor,Analytics}.tsx`): executive overview, IoMT fleet, a real
    threat-monitor timeline, and historical analytics — these were the
    only 4 of the master plan's 11 named views with no component at all;
    10 of 11 are now fully real. The 11th, response alternatives, stays
    partial exactly as before: `PolicyDecision` only carries one chosen
    action, not ranked candidates, so the frontend shows the real chosen
    action + rationale rather than fabricating alternatives the backend
    doesn't have — fixing that needs a backend schema change, not more
    frontend code.
  - **5 new standalone docs**: `docs/{threat-model,api,deployment,
    limitations-and-ethics,reproducibility}.md`.
  - **A real dataset/paper search, not a code change** — and a
    self-correction of this project's first attempt at it. The five
    originally-named benchmark datasets' hosts (and every other external
    host tried) are blocked by this sandbox's own network policy, not
    just unb.ca specifically — confirmed by testing several unrelated
    hosts, not just the original one. The first candidate base paper found
    (Zachos et al. 2025, IEEE Access, DOI 10.1109/ACCESS.2025.3547572) was
    checked again at Darshan's request and does **not** use CICIoMT2024 or
    any publicly released dataset — its title says "dataset generation"
    because it generates its own private Raspberry-Pi testbed data for
    unsupervised novelty/outlier detection (OCSVM, LOF, IsoForest, etc.),
    never released. Pairing it with the unrelated CORA.RDR/Dataverse
    release below would not have supported a real same-dataset comparison,
    so it is dropped as the base paper (kept only as a related-work
    citation on resource-constrained AIDS design).
  - **Corrected base paper, verified to use the same dataset this project
    targets:** Akar, Sahmoud, Onat, Çavuşoğlu & Malondo, "L2D2: A Novel
    LSTM Model for Multi-Class Intrusion Detection Systems in the Era of
    IoMT," *IEEE Access*, vol. 13, pp. 7002-7013, 2025, DOI
    10.1109/ACCESS.2025.3526883. It trains and evaluates directly on
    **CICIoMT2024** (19 classes, 98% reported accuracy) and, like every
    other paper found in this search (Shaikh et al.'s HCLR-IDS, Balhareth &
    Ilyas's tree-based IDS, the Zachos paper above), stops at
    classification — none of them decide what to *do* about a detected
    attack in a way that weighs patient/clinical impact. That gap is this
    project's actual novelty claim: a patient-aware decision layer
    (dual-risk model + policy engine + multi-agent reasoning + verified
    recovery + immutable audit) sitting downstream of detection, not a
    better detector. A real, open (CC-BY-4.0), ML-ready alternative to
    raw CICIoMT2024 was also found — a unified CICIoMT2024 +
    IoMT-TrafficData release on CORA.RDR/Dataverse (DOI 10.34810/DATA3305)
    whose six-class taxonomy (Benign/DDoS/DoS/MQTT/Reconnaissance/Spoofing)
    lines up with this project's own `AttackCategory` enum — useful as a
    faster-to-use ML-ready table, but its own re-extracted features are
    not guaranteed identical to CICIoMT2024's original CSVs, so the exact
    same-dataset comparison to the L2D2 paper's reported 98%/19-class
    number needs the raw CICIoMT2024 CSVs from CIC/unb.ca specifically
    (`datasets/download_ciciomt2024.py` already targets this). The raw
    CICIoMT2024 WiFi+MQTT CSVs were later obtained by hand and are now
    used for the detection baselines below (separate 45-feature pipeline);
    the runtime detector and the Phase 13 ablation harness still use the
    synthetic stand-in until they are re-pointed at it. See
    `datasets/LICENSE_NOTES.md` for the full, sourced writeup.
- **Real CICIoMT2024 detection baselines (19-class, official split).**
  `backend/app/cybersecurity/ciciomt2024.py` loads the real CSVs (labels
  come from file names; there is no label column) and
  `train_ciciomt2024.py` trains and evaluates XGBoost and Random Forest on
  the official capture-level train/test split, scoring the *entire* test
  split (1,614,182 rows). Results and caveats: `evaluation/ciciomt2024_results.md`.
  These models use the dataset's 45 flow features, so they are **not** the
  models the runtime detection service loads (15-feature proxy schema).
- **Patient-safety comparison on the real detector.**
  `backend/app/evaluation/run_real_data_comparison.py` re-runs the five-system /
  six-ablation comparison with the real XGBoost detector over all 1,614,182 test
  rows and 5 device-context seeds (`evaluation/real_data_comparison.md`).
  `full_system` took 0 unsafe autonomous actions on high-stakes trials in every
  seed versus 99.7% for the fixed-response baseline; it still autonomously
  isolates a device on roughly half of the detector's benign false positives, a
  limitation reported rather than hidden. The clinical device context and the
  three LLM-backed agents remain disclosed stand-ins.
- **Confidence-gate experiment.** `backend/app/evaluation/run_confidence_gating.py`
  sweeps a pre-declared grid of detector-confidence thresholds on the same real
  detector (`evaluation/confidence_gating.md`). Confidence separates false alarms
  from real attacks (AUROC 0.989), and sending low-confidence detections to human
  approval cuts the false-alarm isolation rate from about 50% (tau 0.6) to about
  3% (tau 0.95) at the cost of about 3% of real-attack autonomy, with 0 unsafe
  autonomous actions throughout. This is an exploratory curve read off the test
  split, **not a deployable result**: no tau can be chosen on the data it was
  measured on. The validated version is the next bullet.
- **Calibrated confidence gate, tau chosen on validation.**
  `backend/app/evaluation/run_calibrated_gating.py` holds out validation data
  from the training split (whole last capture for multi-capture classes, a
  contiguous tail block with a gap for Benign and ARP_Spoofing, which have one
  capture each), fits one temperature on it, and applies a rule fixed in
  advance (largest tau keeping at least 95% of real-attack autonomy on
  validation). It chose tau = 0.7 on the calibrated confidence. On the untouched
  test split that cuts unnecessary isolation from 50.5% to 41.5% (95% CI 40.0 to
  43.2%) with 99.9% real-attack autonomy retained and 0 unsafe autonomous
  actions: a modest, honest gain, much smaller than the exploratory curve
  suggests. Validation is optimistic for Benign/ARP (validation benign false
  positive rate 1.25% vs 4.14% on test), one training seed, sampled device
  contexts. Report: `evaluation/calibrated_gating.md`. The Policy Engine now has
  the gate as an opt-in rule (`POLICY_MIN_AUTONOMOUS_CONFIDENCE`, off by
  default): it can only turn an autonomous decision into one needing human
  approval, never the reverse, and fails closed when the gate is on and the
  confidence is unknown.
- **Real-flow detector runtime.** `POST /detections/score-flows` scores real
  CICIoMT2024 45-feature flow rows with the trained XGBoost model
  (`RealFlowDetectionService`) and emits the same `DetectionEvent` as the
  15-feature proxy pipeline, with incident and outbox provenance. The two
  pipelines are not interchangeable (different feature sets) and the endpoint
  returns 503 with training instructions if the model artifact is absent.
- **Resilience metrics.** `backend/app/evaluation/run_resilience_metrics.py`
  (`evaluation/resilience_metrics.md`): measured decision-path and detector
  latency (decision path p50 0.016 ms; single-flow detector p50 0.77 ms; about
  32k flows/s batched, on a 2-CPU sandbox), detection delay counted in flows
  (rows carry no timestamps; 20 of 20 attack captures alerted within their first
  flows), and a *modelled* containment delay that depends on an assumed human
  approval time. In the full system 50.0% of alerts wait for a human (100% on
  high-stakes devices); that is the cost side of the safety result, reported
  rather than hidden.
- **Hardening and storage.** Opt-in rate limiting (429 + Retry-After) and
  request-body-size limiting (413), both off by default and in-process;
  `pydantic` pinned; CI gained `frontend` and `e2e` jobs; Postgres-backed
  `NetworkEventStore`/`TelemetryStore` (TimescaleDB hypertables when the
  extension exists, plain tables otherwise); and ranked response alternatives
  on `PolicyDecision`, shown in the dashboard's response panel.
- **Not verified, by deliberate and disclosed decision, not oversight:**
  an actual registry-access build/run verification of Phase 14's Docker setup
  (`docker compose up` could not be run where this was built: container
  registries were unreachable); a live Gemini call exercised end-to-end (the
  wiring is real and tested offline; no `GEMINI_API_KEY` was available); the
  TimescaleDB hypertable branch against a real TimescaleDB server (only plain
  PostgreSQL is available to the tests; retention/compression policies are not
  configured); the new CI `frontend`/`e2e` jobs on GitHub's runners (the same
  commands pass locally). Also not built: a real migration tool (Alembic);
  distributed rate limiting (the limiter is per-process); the IoMT
  simulator's feature schema still differs from CICIoMT2024's 45 features, so
  the proxy pipeline and the real pipeline coexist rather than merge.

If a component isn't listed as implemented above or in
`docs/architecture.md`, it doesn't exist yet.

## Repository layout

```
backend/        FastAPI application — all server-side layers live under app/
frontend/       React/TypeScript SOC dashboard (Vite; see frontend/README.md)
blockchain/     Hyperledger Fabric network config + chaincode
datasets/       Dataset download scripts and license notes (no data committed)
experiments/    Baseline/ablation run configs and trained model artifacts
evaluation/     Metric computation and report generation
configs/        Environment-specific, non-secret configuration
scripts/        Developer tooling (setup, migrations, dataset download)
tests/          Integration and end-to-end tests
docs/           Architecture, threat model, API, and research documentation
infrastructure/ Named by the original plan for Docker Compose + Dockerfiles;
                those actually live at the repo root and beside the code they
                build instead — see infrastructure/README.md
notebooks/      Exploratory analysis only — never production logic
```

Each directory has its own `README.md` describing its purpose and current status
in more detail.

## Local development

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example ../.env   # adjust as needed
pytest
uvicorn app.main:app --reload
```

The SOC dashboard (`frontend/`) talks to this backend over HTTP from its own
origin, so run the backend first, then:

```bash
cd frontend
npm install
npm run test   # Vitest + React Testing Library
npm run build  # tsc -b && vite build
npm run dev    # Vite dev server, default http://localhost:5173
```

The backend's default CORS allowlist (`Settings.cors_allowed_origins`)
already includes the Vite dev server's default origin — see
`backend/app/core/README.md`.

The Phase 11 Scenario A/B end-to-end suite starts its own backend and
frontend processes, so it doesn't need either of the above already running:

```bash
cd backend && source .venv/bin/activate
pytest -c ../tests/pytest.ini ../tests/e2e
```

See `tests/README.md` for what this suite actually proves and what it needs installed.

### Docker

```bash
cp .env.example .env   # adjust as needed, especially API_PORT/FRONTEND_PORT if either is taken
docker compose up --build
```

Brings up backend + frontend (served via nginx, not the Vite dev server) +
Postgres/TimescaleDB as three services from one `docker-compose.yml` —
Section 19's Phase 14 gate. The dashboard is then at
`http://localhost:${FRONTEND_PORT:-5173}`, calling the backend at
`http://localhost:${API_PORT:-8000}`; `docker-compose.yml` wires
`CORS_ALLOWED_ORIGINS` and the frontend's build-time `VITE_API_BASE_URL`
to match each other automatically if you change either port.

**Hyperledger Fabric is deliberately not a compose service.** This is
Phase 8's own locked decision, not something Phase 14 overlooked: bring
up `blockchain/network/` separately, by its own README, using the native
binaries that decision settled on.

**Disclosure that matters more than the above:** none of this has been
build- or run-verified in this project's development sandbox. That
sandbox's network policy blocks every container registry tried against
it — Docker Hub, ghcr.io, mcr.microsoft.com, and gcr.io all returned 403
Forbidden, confirmed by actually trying to pull `python:3.12-slim` to
build the existing `backend` image, which is also how Phase 8 originally
found this same block for Fabric. So no base image in this file
(`timescale/timescaledb`, `python:3.12-slim`, `node:22-alpine`,
`nginx:1.27-alpine`) can be pulled there, for any service, and nothing
here has ever actually run `docker compose up` to completion. What *has*
been checked, without needing to pull anything: `docker compose config`
parses and interpolates this file cleanly (verified from a clean clone,
with real variable substitution — not just "looks right"). Verify an
actual `docker compose up --build` in an environment with registry
access before treating this gate as more than "written and
config-validated" — see `docker-compose.yml`'s own top comment for the
same disclosure in place.

## License

See [`LICENSE`](LICENSE).
