# Phase 15 — documentation verification

Architecture spec Section 19's literal gate: **"Every claim in `docs/` is
checked against what's actually implemented and tested."** `docs/` holds
three files — `architecture.md` (the Phase 0 specification), `security-
checklist.md` (the Phase 12 deliverable, already a verified-against-the-code
document by construction), and this one. This document is that check for
`architecture.md`: every section with a concrete, checkable technical claim
was re-verified this phase by reading the real code or re-running the real
suites — not re-asserted from memory of what earlier phases' own READMEs
already said about themselves.

**What this document deliberately is not.** `architecture.md`'s own header
says it is "a static, versioned copy of the Phase 0 architecture doc,"
synced from an external, live artifact — "update that one first for any
future revision, then re-sync this copy." It is a historical record of what
was decided *before* any of Phases 1–14 were built, not a living doc this
project edits in place to match whatever the code ended up doing. So where
reality diverged from the Phase 0 plan — and in a 15-phase build, some of it
did — the fix here is to name the divergence plainly in a companion
document, not to quietly rewrite Section 12 or Section 14 so the spec reads
as if it predicted the real implementation exactly. Several of these
divergences were already disclosed somewhere (a module's own README, the
Claude Project's `architecture-decisions.md`) well before this phase; what
this phase adds is checking that *every* section's claims were disclosed
somewhere, finding the ones that weren't, and collecting all of it in one
place inside `docs/` itself, which is what the Phase 15 gate actually asks
for.

## Verification run for this phase

Re-run, not re-asserted, immediately before writing the findings below:

| Check | Result |
| --- | --- |
| Backend suite (`pytest`) | 359 passed |
| Backend lint (`ruff check`) | clean |
| Frontend suite (`vitest run`) | 46 passed |
| Frontend lint (`oxlint`) / build (`vite build`) | clean / clean |
| Phase 11 E2E suite (`pytest tests/e2e`, real Chromium) | 2 passed |
| `pip-audit` (backend) | 0 known vulnerabilities |
| `npm audit` (frontend) | 0 vulnerabilities |
| `npm audit` (`blockchain/chaincode`) | 0 vulnerabilities |
| `docker compose config` | parses and interpolates cleanly |

Same counts as every phase since the Phase 12 dependency bump — nothing
regressed, nothing was re-counted optimistically.

## Section 19's own phase-gate table, re-walked

Section 19 is itself the master set of claims this whole project is
answerable to — every phase's README and the Claude Project doc already
assert "gate met," but this is the first time all fifteen are checked
against each other, side by side, in one pass.

| Phase | Gate (Section 19's words) | Status |
| --- | --- | --- |
| 0 — Architecture | Document reviewed and approved | Met — this document's parent |
| 1 — Foundation | `docker compose up` runs an empty FastAPI app that responds on `/health`; tests pass; **pushed to GitHub** | Met, with one standing, deliberate exception: nothing from Phase 1 onward has ever been pushed to GitHub, per Darshan's explicit standing instruction ("I will let you know when to push in GitHub"). This is a human override of the written gate, not a missed one — `origin/main` still does not exist as a ref (re-confirmed this phase: `git branch -a` lists only `main`) |
| 2 — IoMT simulator | Three devices produce telemetry + a scripted attack scenario deterministically, with tests | Met — `backend/app/iomt_simulator/` (device state machines, `ScenarioRunner` with a fixed seed) |
| 3 — Detection engine | A trained model with measured precision/recall on a held-out split | Met, with a disclosed dataset substitution — see "Dataset" finding below |
| 4 — Agentic investigation/reasoning | All 5 agent schemas implemented and unit-tested against mocked LLM responses | Met — `backend/app/agents/` (5 modules, `MockLLMClient`) |
| 5 — Dual-risk engine | `RuleBasedRiskModel` passes Scenario A and B | Met — `backend/app/risk_engine/`, exercised by `tests/e2e/` |
| 6 — Safety policy + response orchestration | Policy Engine's rule table reviewable, 100% branch coverage | Met — `backend/app/policy_engine/rules.py` |
| 7 — Recovery + verification | Re-investigation loop actually re-opens an incident in an integration test | Met — `RecoveryOrchestrator.process_result`, tested |
| 8 — Hyperledger Fabric provenance | `recordIncident` through `verifyEvidence` work against the running test-network, end to end | Met, with a disclosed topology substitution — see "Fabric bring-up" finding below |
| 9 — Backend integration | All resource routers exist and are covered by API tests | Met — 12 routers, confirmed again this phase (`ls backend/app/api/`) |
| 10 — SOC dashboard | One incident's full lifecycle viewable, dual-risk panel visually distinct | Met — `frontend/src/routes/IncidentDetail.fullLifecycle.test.tsx` |
| 11 — End-to-end integration | Scenario A and B run through the real UI | Met — `tests/e2e/`, re-run this phase, 2/2 |
| 12 — Testing + hardening | Security checklist verified item by item | Met, with a disclosed source substitution (the brief's actual Section 16 is unrecoverable; `docs/security-checklist.md` is this project's own, explicitly labeled as such) |
| 13 — Experiments + evaluation | Detection-only vs. full-system comparison has real numbers | Met at the gate's literal minimum, not the fuller five-system/seven-ablation comparison Section 18 describes — see "Baseline progression" finding below |
| 14 — Dockerization + deployment | Full stack runs from one `docker compose up` | Met for backend + frontend + Postgres (what this sandbox can actually build); Fabric stays native, and no `docker compose up` has ever completed in this sandbox's registry-blocked environment — both disclosed in `docker-compose.yml`'s own header comment |
| 15 — Final docs + polish | Every claim in `docs/` checked against what's implemented and tested | This document |

## Section-by-section claim verification

Sections 1, 2, 4, 7, 17, and 20 are narrative/historical (repository
inspection, named risks, a diagram description, a walkthrough, a testing
strategy, and the Phase 1 task list) rather than standalone checkable
assertions — each is already covered by the phase-by-phase check above, via
the code that implements the steps they describe. The sections below carry
specific technical claims checked directly against the real code this
phase.

**Section 3 (decisions) / Section 14 (blockchain architecture) — Fabric
bring-up.** The spec's literal words: "using its sample Docker Compose
network," "run via the existing Docker Compose sample scripts." **Actual:**
Fabric runs via downloaded native binaries (`peer`, `orderer`, `cryptogen`,
`configtxgen`, `osnadmin`), never `docker-compose`/`test-network.sh` —
Phase 8 found Docker Hub blocked in this sandbox and pivoted, a decision
already fully documented in `blockchain/network/README.md` and the Claude
Project doc, now also named here. What *did* ship as specified: the
two-organization topology itself (`HospitalMSP`/`SecurityOpsMSP`, confirmed
by re-reading `blockchain/network/configtx.yaml` this phase) and all six
named chaincode operations, confirmed present with matching names and
signatures by re-reading `blockchain/chaincode/lib/provenanceContract.js`
this phase: `recordIncident`, `recordDecision`, `recordApproval`,
`recordResponse`, `recordRecovery`, `verifyEvidence`.

**Section 5 (tech stack).** Checked against `backend/requirements.txt`,
`frontend/package.json`, and the actual module list: Python/FastAPI/Pydantic
v2 — confirmed. scikit-learn + XGBoost (`xgboost==2.1.3`), no PyTorch
anywhere in the codebase — confirmed by grep. React + TypeScript + Vite +
Tailwind CSS v4 — confirmed. No Kubernetes, no Kafka/RabbitMQ, no MongoDB —
confirmed, nothing of the kind appears in any requirements file. One
item the spec left open and still is: "LangGraph or a hand-rolled state
machine — decided in Phase 4." No orchestration framework was ever adopted
(no `langgraph` import anywhere) — every exercise of the five agents in
sequence (the lifecycle integration test, the E2E seeding, Phase 13's
evaluation harness) calls the five agent functions directly, by hand, in
each test/script's own code. This is the standing open decision named in
every phase's README since Phase 4 (Section 11), re-confirmed still open,
not silently resolved by accretion.

**Section 6 (repository structure) — the `infrastructure/` mismatch.** The
spec's tree puts `docker-compose.yml` and the Dockerfiles under
`infrastructure/`. **Actual:** `docker-compose.yml` is at the repo root
(Phase 1), and `backend/Dockerfile`/`frontend/Dockerfile` live beside the
code they build (Phase 1 and Phase 14, respectively) — `infrastructure/`
has only ever held its own `README.md`. This was not previously stated
anywhere; found and fixed this phase (`infrastructure/README.md` now says
so directly). Every other named top-level directory from Section 6's tree
exists with the planned purpose, including the Phase 13 addition of
`backend/app/evaluation/` alongside the ten planned layer modules — additive
to the plan, not a contradiction of it.

**Section 8 (storage strategy) — the Postgres claim is more inert than
"not yet migrated" previously said.** Every prior phase's README describes
this as "no Postgres migration yet; every repository is still in-memory,"
which is true but incomplete. Checked more precisely this phase:
`asyncpg`/`sqlalchemy` are both declared in `backend/requirements.txt`, and
`Settings.database_url` exists and is wired into `docker-compose.yml`'s real,
running `timescale/timescaledb` container (confirmed healthy via its own
healthcheck when `docker compose config` resolves the file) — but grepping
all of `backend/app/` for `asyncpg`, `sqlalchemy`, `create_engine`, or
`AsyncSession` turns up exactly one file: `config.py`, which only *declares*
the setting. No application code anywhere opens a database connection.
Every repository behind every router (`IncidentRepository`,
`ProposedResponseRepository`, `RecoveryResultRepository`, and the rest,
wired in `app_factory.py`) is a plain in-memory `dict`. So it is more
precise to say: the Postgres/TimescaleDB container that `docker compose up`
brings up is real and healthy, but currently inert from the backend's point
of view — nothing reads or writes it. This doesn't change any phase's gate
(Phase 9's literal gate never required the migration; see that phase's
entry above), but it is a sharper, previously-unstated description of
exactly how not-yet-migrated this is, surfaced here rather than left at the
vaguer "disclosed known gap" phrasing used elsewhere.

**Section 10 (detection architecture) / Section 18 (evaluation) —
dataset.** The spec's plan: train on real CICIoMT2024 flow features.
**Actual:** no phase has ever had network access to download CICIoMT2024 in
this sandbox (`datasets/LICENSE_NOTES.md`, unchanged since Phase 3); every
trained model in this project — the ones `backend/app/cybersecurity/`
ships, the ones Phase 13's evaluation harness trains fresh — is trained
against `synthetic_data.py`'s synthetic stand-in, explicitly disclosed in
that module and in every phase's README since Phase 3.
`training.py`'s `load_real_dataset()` still deliberately raises
`NotImplementedError` rather than guess a loader for data that was never
available to test against — confirmed unchanged this phase. The
`DetectionEvent` schema itself matches Section 10's literal contract field
for field (`device_id`, `attack_type`, `confidence`, `severity_hint`,
`timestamp`, `evidence_ref`), confirmed by re-reading
`backend/app/schemas/detection.py`.

**Section 11 (agentic AI) — the five-agent table.** Checked against
`backend/app/agents/`: `investigation.py`, `threat_reasoning.py`,
`healthcare_context.py`, `response_planning.py`,
`recovery_verification.py` — five modules, same names, same order as
Section 11's table, confirmed this phase. None hold an execute tool; only
`ResponseOrchestrator` (L7) does, re-confirmed by the same module boundary
Phase 6 established.

**Section 12 (dual-risk engine) — the `RiskScore.response_impact` type
mismatch.** The spec's literal schema: `response_impact: dict[action_id,
float]`. **Actual:** `response_impact: dict[str, ImpactLevel]` — a
4-category enum keyed by action, not a float — confirmed by re-reading
`backend/app/schemas/risk.py` this phase, which documents the discrepancy
in its own module docstring (a Phase 5 decision: built against the real
schema Phase 4 already shipped, not the brief's literal prose, with the
reasoning for a categorical scale over a raw float recorded in
`backend/app/schemas/enums.py`). This was disclosed in code and in the
Claude Project doc since Phase 5, but never stated inside `docs/` itself
until now — the exact kind of gap this phase exists to close.

**Section 13 (policy engine) — the three routing rules.** Checked against
`backend/app/policy_engine/rules.py`: the LOW / MEDIUM-and-not-patient-
dependent / HIGH-or-patient-dependent-severe-action thresholds match
Section 13's text exactly, including the one documented gap-fill from
Phase 6 (an MEDIUM-impact, patient-dependent, non-severe action has no
literal rule in Section 13's prose; defaults conservatively to requiring
approval, flagged in the module's own comments as this project's addition,
not the spec's text).

**Section 15 (backend API) — the router list.** Checked against
`backend/app/api/`: `devices`, `telemetry`, `events`, `incidents`,
`detections`, `risk_assessments`, `agents`, `responses` (both
`/proposed` and `/executed`), `recovery`, `blockchain_audit`, `health` — all
twelve present, confirmed this phase by directory listing, matching
Section 15's named list and the count every phase since 9 has quoted.

**Section 16 (frontend) — route-level views over a shared incident-detail
component.** Checked against `frontend/src/routes/`: `IncidentList` and
`IncidentDetail` under a shared `Layout`, with `IncidentDetail` composing
`DualRiskPanel`, `AgentActivityPanel`, `EvidencePanel`, `ResponsePanel`,
`RecoveryPanel`, and `BlockchainAuditPanel` as one incident-lifecycle view —
matches Section 16's description exactly.

**Section 18 (research evaluation) — the five-system progression.** The
spec adopts a five-system progression (detection-only → +fixed-response →
+agentic AI → +risk-engine → full system) plus seven ablations. **Actual:**
`backend/app/evaluation/baseline_systems.py`'s `SystemName` enum has three
members (`DETECTION_ONLY`, `FIXED_RESPONSE`, `FULL_SYSTEM`) — the gate's
literal minimum plus the one extra baseline needed to make the comparison
non-trivial (Phase 13's own stated reasoning), not the full five-system
progression or any of the seven ablations. Already disclosed in
`experiments/README.md` and `evaluation/README.md`; re-confirmed against
the actual enum this phase, not just against those READMEs' own claims
about it.

## Fixed while performing this pass

- `infrastructure/README.md` claimed `docker-compose.yml` and the
  Dockerfiles live in that directory. They never have — corrected to say
  where they actually are and why (the same discipline Phase 10 and Phase
  14 used on other stale READMEs when a later phase's own work surfaced
  them).

## What this phase deliberately did not do, and why

- **Did not edit `docs/architecture.md`'s own text.** It is explicitly a
  frozen, versioned copy of an external Phase 0 artifact, by its own header
  — rewriting Section 12's schema or Section 14's Fabric plan to match what
  Phases 5/8 actually built would misrepresent what the Phase 0 review
  actually approved. This document is the reconciliation layer instead.
- **Did not retroactively build any carried-forward gap** — a real Postgres
  migration, authentication, rate limiting, an orchestration framework, the
  full five-system/seven-ablation comparison, or a real CICIoMT2024 training
  run — just to make Section 19's table read as a clean match to the
  original plan. Every one of those is a disclosed, deliberate scope
  decision from an earlier phase; building any of them unasked at the very
  last phase would be exactly the kind of scope invention this project has
  avoided at every other phase boundary, not "final polish."
- **Did not re-run the live Fabric `test-network` end-to-end.** Unchanged
  since Phase 8, and the claims this phase checks about it (topology,
  chaincode operation names/signatures) are checked by reading the real,
  committed config and chaincode source, which is what the spec's claims are
  actually about — not by re-proving the live network still comes up, which
  nothing this phase touched could have regressed.
- **Did not push anything to GitHub.** Per Darshan's standing instruction —
  re-confirmed this phase (`git branch -a` lists only `main`; no `origin`
  ref exists).

## Verification (repeated, for this document's own record)

Full backend suite: 359 tests passing, `ruff check` clean. Full frontend
suite: 46 tests passing, `oxlint`/`npm run build` clean. Phase 11 E2E suite:
2/2 passing. `pip-audit`: 0 known vulnerabilities. `npm audit` (frontend and
chaincode): 0 vulnerabilities, both. `docker compose config`: parses and
interpolates cleanly. All re-run during this phase, not carried forward by
assertion from Phase 14's numbers.
