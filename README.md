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
- **Not yet built:** Phases 11–15 — end-to-end integration exercised
  through the real UI (not just backend tests), a security hardening pass,
  experiments/evaluation with real reported numbers, a Dockerized
  full-stack deployment, and a final documentation pass. There is still no
  automatic multi-agent orchestrator; the five agents are sequenced
  manually wherever they're exercised (tests, the lifecycle integration
  test above), standing in for an orchestration decision the architecture
  doc deliberately leaves open.

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

Or via Docker Compose (backend + Postgres/TimescaleDB):

```bash
docker compose up
```

## License

See [`LICENSE`](LICENSE).
