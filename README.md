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

This project is under active development, built in phases. See
[`docs/architecture.md`](docs/architecture.md) for the full architecture
specification, the decisions made and why, and the current development phase.

**Phase 1 (foundation) is the current state of this repository.** No detection
model, agent, risk engine, policy engine, blockchain integration, or frontend is
implemented yet — those arrive in later phases. Nothing in this README or in
`docs/` claims otherwise; if a component isn't listed as implemented in
`docs/architecture.md`, it doesn't exist yet.

## Repository layout

```
backend/        FastAPI application — all server-side layers live under app/
frontend/       React/TypeScript SOC dashboard (not yet built)
blockchain/     Hyperledger Fabric network config + chaincode (not yet built)
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

Or via Docker Compose (backend + Postgres/TimescaleDB):

```bash
docker compose up
```

## License

See [`LICENSE`](LICENSE).
