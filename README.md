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

This project is under active development, built in 16 phases (0–15). See
[`docs/architecture.md`](docs/architecture.md) Section 19 for the full phase
plan and gates, and the Claude Project doc `claude/architecture-decisions.md`
for phase-by-phase decisions. As of this commit:

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
- **Not yet built:** Phases 14–15 — a Dockerized full-stack deployment and a
  final documentation pass; the fuller five-system/seven-ablation
  comparison beyond Phase 13's gate. There is still no automatic
  multi-agent orchestrator; the five agents are sequenced manually
  wherever they're exercised (tests, the lifecycle integration test above,
  the Phase 11 E2E seeding, Phase 13's evaluation harness), standing in for
  an orchestration decision the architecture doc deliberately leaves open.
  There is also still no rate limiting or authentication layer (disclosed
  known gaps, Phase 12 security checklist).

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
infrastructure/ Docker Compose and Dockerfiles
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

Or via Docker Compose (backend + Postgres/TimescaleDB):

```bash
docker compose up
```

## License

See [`LICENSE`](LICENSE).
