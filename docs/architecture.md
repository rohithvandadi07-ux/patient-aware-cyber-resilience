# Patient-Aware Cyber Resilience — Architecture Specification

Oct 7, 2026 · @Darshan

> This is a static, versioned copy of the Phase 0 architecture doc, committed here so it travels with the code it governs. The live, editable version (with the interactive component diagram) is at https://claude.ai/artifact/D52PsBDN5LmNGmTGF4YHi8 — update that one first for any future revision, then re-sync this copy.
>
> **Phase 15 note:** this document describes the plan as approved before Phases 1–14 were built, not necessarily what they ended up building — several sections (Fabric's Docker-vs-native bring-up, the real `RiskScore.response_impact` schema, the dataset actually trained on, the three-system vs. five-system evaluation) diverged from the plan for reasons disclosed phase by phase as they happened. See `docs/phase15-verification.md` for the full, section-by-section reconciliation — read that one for what's actually true today.

Architecture and foundation planning for a research-grade, patient-aware autonomous cyber-resilience platform for healthcare IoMT. This document is Phase 0 deliverable: no implementation code is written against it until Darshan approves it.

## 1. Repository inspection

The brief's "current state" section does not match reality. Actual findings:

| Claim in brief | Actual state found |
| --- | --- |
| "Local repository is initialized" | No git repository existed anywhere in the environment |
| "Local branch is MAIN" | N/A — nothing to branch |
| "GitHub remote is already configured" | No remote was configured; `rohithvandadi07-ux/patient-aware-cyber-resilience` exists on GitHub and is reachable read-only (anonymous `git ls-remote` returns zero refs — it is genuinely empty), but push credentials are not yet verified from this environment |
| "Repository is currently empty" | True, but there was no repository to be empty — the working directory itself was the environment's home directory, cluttered with unrelated dotfiles (`.cache`, `.config`, `.ssh`, `.npm`, etc.) |

I corrected this without waiting for approval, since it is pure setup with no architectural consequence: created a dedicated project directory, ran `git init -b main` there, set the local git identity, and added `origin` pointing at the GitHub URL from the brief. No commits have been made yet — that happens at the Phase 1 checkpoint, after this document is reviewed.

Open item: GitHub push access from this session has not been proven. The read side works anonymously because the repo is public; the write side needs either a working `gh auth` token or credentials supplied another way. I'll surface this concretely at the Phase 1 git-push step rather than assume it works.

## 2. Architectural risks and ambiguities

Eight decisions carry enough weight that getting them wrong late is expensive. Each is resolved in Section 3, but is named here first because the brief leaves it genuinely open rather than implying one answer.

**Risk 1 — Hyperledger Fabric is heavy for a solo build.** Fabric is still actively maintained (v2.5.x and v3.1.x both shipped releases in mid-2026) and remains the default academic citation for permissioned blockchain, but multi-org MSP/CA setup, pluggable consensus configuration, and Go/Java/Node chaincode tooling are a real time sink for one person. The brief itself says "preferred" and "unless architecture review identifies a strong reason otherwise" — that review is due now, not deferred.

**Risk 2 — dataset selection is unscientific if done casually.** The brief names five candidate datasets but forbids picking one arbitrarily. CICIoMT2024, ECU-IoHT, and WUSTL-EHMS-2020 differ enormously in what they actually offer: pure network-attack labels vs. genuine network+clinical-telemetry fusion. Picking the wrong one undermines the central research claim (dual-risk decisioning needs *both* cyber and clinical signal).

**Risk 3 — LLM-driven agents must not be allowed to touch safety-critical decisions directly.** The brief is explicit that agents must never bypass the deterministic policy layer, but the architecture has to enforce this structurally (schema boundaries, no agent-held "execute" capability), not just as a design intention, or it quietly erodes as code accretes.

**Risk 4 — "agentic" can collapse into a single prompt chain if not given real state and tool boundaries.** Five named agents with structured I/O is the right shape, but the risk is building them as five prompts calling one LLM with no persisted state, no tool-call audit trail, and no ability to independently test one agent's logic. That is agentic in name only.

**Risk 5 — the dual-risk formula is undefined and must stay provisional.** The brief is correct that `Decision = f(cyber_risk, clinical_criticality, response_impact)` is only conceptual. Committing to a specific weighted formula in Phase 1 would be premature; the architecture needs a pluggable risk-scoring interface so the actual function can be designed later from literature and ablation, without an API rewrite.

**Risk 6 — simulator fidelity vs. dataset realism is a seam, not a single pipeline.** Device simulation (synthetic telemetry + clinical context) and dataset-driven detection (real CICIoMT2024/WUSTL flow records) are different kinds of data that must be joined at the "incident" boundary — a detection event references a simulated device's context, it is not generated by replaying the dataset through the simulated device. Conflating these two would corrupt both the ML evaluation and the realism of the simulator.

**Risk 7 — blockchain latency must not sit on the hot path.** Every security/decision event triggering a synchronous Fabric transaction would make the whole closed loop as slow as the blockchain layer. Provenance writes need to be asynchronous relative to response execution.

**Risk 8 — scope creep across 10 conceptual layers invites a 3-week rewrite in month 2.** Building all 10 layers' interfaces up front, before any one of them has a working vertical slice, is a classic way to discover a structural mistake only after a lot of code exists. Phase 1 deliberately stops at foundation, not interfaces for all 10 layers.

## 3. Decisions finalized for this phase

**Blockchain: Fabric's own `test-network` topology, not a bespoke multi-org network (resolves Risk 1).** This keeps "Hyperledger Fabric" as the literal, citable technology — the brief's preference is honored — while using its sample Docker Compose network (two orgs: Hospital, SecurityOps; one orderer) instead of standing up a production-grade multi-org deployment. This is an accepted pattern in academic prototypes: the trust model being demonstrated (permissioned ledger, MSP-based identity, chaincode-enforced writes) does not depend on topology size. Revisit only if a reviewer specifically objects.

**Datasets: CICIoMT2024 as the primary detection dataset, WUSTL-EHMS-2020 as a secondary fusion-relevant dataset, ECU-IoHT not used initially (resolves Risk 2).** CICIoMT2024 (UNB/CIC) is the current field baseline — 40 devices, 18 attacks across DoS/DDoS/recon/MQTT/spoofing, large enough for credible train/test splits, actively cited in 2024–2025 literature. WUSTL-EHMS-2020 is smaller (16,318 rows, 2 attack classes: MITM spoofing + injection) but is the only one of the three that fuses real network-flow features with real physiological/biometric features in the same row — directly relevant to validating that clinical context changes the right response, not just whether an attack was detected. ECU-IoHT is older, less documented, and not treated as a field baseline; it is not disqualified, just deferred until Phase 3 evaluation shows a specific gap it would fill. None of these are downloaded or processed yet — that is Phase 3 work, done with explicit license/accessibility verification first.

**Agent/policy boundary: agents never hold an execute capability (resolves Risk 3).** The Response Planning Agent's only output is a structured `ProposedResponse` object. It cannot call `execute_safe_action` itself. Only the Policy Engine, given that structured object, decides autonomous-vs-approval routing and only the Response Orchestrator (a separate, non-agentic, deterministic service) calls execution tools. This is enforced by which service holds which tool binding, not by prompt instruction.

**Agent state: each agent is a real service with persisted input/output records, not a prompt template (resolves Risk 4).** Every agent call writes its structured input and output to the incident's agent-trace table before returning. This makes each agent's logic independently testable (given this evidence, does the Threat Reasoning Agent produce a sane assessment?) without running the full chain, and gives the SOC dashboard's "Agent Activity" section real data rather than invented narration.

**Risk scoring: a versioned, pluggable `RiskModel` interface; v0 is a transparent rule-based scorer, not a trained model (resolves Risk 5).** `calculate_risk(cyber_risk, clinical_criticality, response_impact) -> RiskScore` is an interface with one initial implementation: an explicit, documented rule table (e.g., ventilator + high patient-dependency + any shutdown-class response → forced human approval, regardless of cyber severity). This is intentionally simple and auditable for Phase 5; replacing it with a learned or weighted-sum model is a later, explicitly evaluated experiment, not a Phase 5 deliverable.

**Simulator/dataset seam: the simulator generates device state and synthetic *live* telemetry; dataset records are replayed as labeled *historical* detection-training data, and the two meet only at the Incident object (resolves Risk 6).** The detection engine is trained/evaluated offline against CICIoMT2024/WUSTL rows. At runtime, the simulator's own network-event generator (which can inject scripted attack scenarios) feeds the *same trained model* to produce live detections. An Incident always carries a reference to a simulated device's live context (criticality, patient dependency, current state) — never a dataset row's metadata, which has none of that.

**Blockchain writes are asynchronous and batched at the decision/provenance boundary only (resolves Risk 7).** Telemetry and network events never touch the chain. Only six event types are committed: incident recorded, decision recorded, approval recorded, response recorded, recovery recorded, evidence-hash verified. Each is pushed to a queue; a separate worker process writes to the chain and updates the off-chain record with the resulting transaction ID once confirmed. Response execution does not wait on this.

**Phase 1 builds foundation only: config, logging, schemas, API skeleton, test harness — no detection, no agents, no blockchain, no real simulator logic (resolves Risk 8).** Section 20 gives the literal file list.

## 4. Component architecture

[Diagram: 10-layer closed-loop architecture — simulator through SOC dashboard. The interactive version lives in the full architecture doc: https://claude.ai/artifact/D52PsBDN5LmNGmTGF4YHi8]

L6 (Safety/Policy Engine, highlighted) is the only layer with execution authority — L4's agents produce proposals, L6 decides. L9 (blockchain) sits off the main spine deliberately: it receives decision/provenance events asynchronously from L5–L8 and never blocks the response path. L10 is bidirectional: it reads every layer for display, and is where a human approves or rejects an L6-flagged high-impact action — that approval flows back into L6 before L7 is allowed to execute. The dashed loop on the left is the brief's explicit requirement: if L8 (Recovery Verification) finds containment failed, the incident re-opens at L4 rather than silently closing.

## 5. Technology stack

| Layer | Technology | Why |
| --- | --- | --- |
| Backend API | Python 3.11+, FastAPI, Pydantic v2 | Brief's preference; FastAPI gives async I/O (needed for the non-blocking blockchain writes in Risk 7) and auto-generated OpenAPI for every layer's API surface |
| ML / detection | scikit-learn first, PyTorch only if evidence from Phase 3 justifies a deep model | Brief requires scientifically justified baselines before advanced models — start with Random Forest / XGBoost on CICIoMT2024 flow features (standard baseline in the literature), justify anything heavier with a measured accuracy/latency tradeoff |
| Agentic AI | A thin internal orchestration layer (LangGraph or a hand-rolled state machine — decided in Phase 4, not now) behind a model-agnostic `LLMClient` interface | Brief forbids hardcoding one LLM; the interface matters more than the orchestration library at this stage |
| Relational metadata | PostgreSQL | Devices, incidents, agent traces, approvals, users — relational integrity matters here (an incident must reference a real device) |
| Time-series telemetry | TimescaleDB (a Postgres extension, not a separate database) | Keeps storage to one engine instead of adding InfluxDB as a second system to operate; Postgres-compatible, so the same driver/ORM works for both relational and time-series data |
| Blockchain | Hyperledger Fabric, `test-network` topology (2 orgs: Hospital, SecurityOps) | Per Decision in Section 3 |
| Frontend | React + TypeScript, Vite, a component library (Tailwind or similar — decided in Phase 10) | Brief requires a professional SOC-grade UI, not a generic admin template; React/TS is the ecosystem default for this and keeps the agent-activity and risk-breakdown views componentized |
| Containerization | Docker Compose for local dev; no Kubernetes at this stage | Brief flags against premature over-engineering; Fabric's `test-network` already assumes Docker Compose |
| Testing | pytest (backend), Vitest + React Testing Library (frontend), deterministic simulator fixtures for scenario tests | Matches Section 17 |

No message broker (Kafka/RabbitMQ) in Phase 1–4. The blockchain write queue (Risk 7) starts as a Postgres-backed outbox table with a polling worker — simplest thing that gives asynchronous, auditable writes. A real broker is an upgrade to consider only if throughput experiments in Phase 13 show the outbox is the bottleneck.

## 6. Repository structure

Close to the brief's proposed layout, with two changes: `backend/` is organized by the brief's own layer boundaries rather than generically, and `agents/`, `cybersecurity/`, `risk_engine/`, `response_engine/`, `recovery/` live as installable packages under `backend/app/` rather than as siblings of it — they are not independent services, they are modules of one FastAPI app that import each other through defined interfaces. Keeping them as top-level siblings invites circular imports and unclear ownership once they need to call each other (the Policy Engine calling the Risk Engine, the Orchestrator calling the Response Engine).

```
patient-aware-cyber-resilience/
├── backend/
│   └── app/
│       ├── api/                 # FastAPI routers per resource
│       ├── core/                # config, logging, security, dependencies
│       ├── schemas/             # Pydantic models — the structured contracts between layers
│       ├── iomt_simulator/      # L1
│       ├── telemetry/           # L2
│       ├── cybersecurity/       # L3 — detection engine
│       ├── agents/              # L4 — 5 agents + orchestration
│       ├── risk_engine/         # L5
│       ├── policy_engine/       # L6
│       ├── response_engine/     # L7
│       ├── recovery/            # L8
│       ├── blockchain/          # L9 — Fabric client + outbox worker
│       └── repositories/        # DB access layer, one per aggregate
├── frontend/                    # L10 — React/TS SOC dashboard
├── blockchain/
│   ├── network/                 # Fabric test-network config, docker-compose
│   └── chaincode/               # recordIncident, recordDecision, etc.
├── datasets/                    # download scripts + license notes, gitignored raw data
├── experiments/                 # Phase 13 — baselines, ablations, run configs
├── evaluation/                  # metric computation, report generation
├── configs/                     # environment-specific YAML, not hardcoded in code
├── scripts/                     # dev setup, dataset download, migrations
├── tests/                       # integration + e2e (unit tests live beside their module)
├── docs/                        # architecture, threat model, API, etc.
├── infrastructure/              # docker-compose.yml, Dockerfiles
├── notebooks/                   # exploratory dataset/model analysis only — never production logic
├── .github/workflows/           # CI
├── .env.example
├── .gitignore
├── docker-compose.yml
├── README.md
└── LICENSE
```

Phase 1 creates the skeleton of every directory above with a `README.md` stating its purpose, but populates only `backend/app/core/`, `backend/app/schemas/` (starter schemas only), the test harness, configs, and the documentation/git/Docker foundation — see Section 20 for the literal list.

## 7. Data flow

Walking one incident through the architecture diagram above, concretely:

1. The simulator (L1) runs a scripted attack scenario against a simulated ventilator — e.g. a spoofed command injection. It emits network events and an altered device state.
2. The collector (L2) timestamps and stores these as rows in the time-series store, tagged with `device_id`.
3. The detection engine (L3) scores the event stream; a feature vector crosses its trained threshold and it emits a `DetectionEvent {device_id, attack_type, confidence, timestamp}`. This creates an `Incident` in `status=detected`.
4. The Investigation Agent (L4) is invoked with the incident ID. It calls read-only tools (`get_logs`, `get_network_events`, `get_telemetry`) to build an `InvestigationReport {evidence, timeline, affected_devices, observations, confidence}`. This and every subsequent agent call writes its input/output to the incident's agent-trace table (Section 3, Risk 4 resolution).
5. The Threat Reasoning Agent consumes the `InvestigationReport` and produces a `ThreatAssessment {attack_type, severity, confidence, propagation_risk, reasoning_summary}`.
6. The Healthcare Context Agent, in parallel, calls `get_device_state` against the simulator's device registry and produces `ClinicalContext {device_criticality, patient_dependency, clinical_impact_level, safety_constraints}` — this is where "ventilator, patient-dependent, currently in use" enters the picture.
7. The Risk Engine (L5) takes the `ThreatAssessment` and `ClinicalContext` and calls `calculate_risk(...)`, returning a `RiskScore {cyber_risk, clinical_risk, response_impact_per_candidate}`.
8. The Response Planning Agent proposes candidate actions (e.g. "isolate network segment" vs. "rotate device credentials" vs. "shut down") as a `ProposedResponse {candidate_actions, security_benefit, clinical_impact, recommended_action, rationale}` — but cannot execute any of them.
9. The Policy Engine (L6) evaluates `ProposedResponse` against its deterministic rule table. For a ventilator with active patient dependency, any shutdown-class action is routed to `requires_human_approval=true` regardless of cyber severity; a lower-impact action like network isolation may be auto-approved.
10. If approval is required, the SOC dashboard (L10) surfaces the incident with its full reasoning chain; a human approves or rejects. That decision is written back to L6.
11. The Response Orchestrator (L7) executes only the action L6 has cleared — calling the simulator's own command interface, never touching real infrastructure (there is none; it's simulated).
12. The Recovery Verification Agent (L8) re-checks device/network state after a cooldown. Success closes the incident; failure re-opens it at step 4 with the new evidence appended (the dashed loop in Section 4's diagram).
13. Independently and asynchronously, every state transition from step 3 onward (incident, decision, approval, response, recovery) is appended to the outbox table; a worker commits the corresponding chaincode transaction to Fabric and writes the resulting transaction ID back to the off-chain record. This never blocks steps 9–12.

## 8. Storage strategy

| Data category | Store | Notes |
| --- | --- | --- |
| Device registry, incidents, approvals, users | PostgreSQL (relational tables) | Foreign keys enforce that an incident always references a real device; this is where referential integrity actually matters |
| Device telemetry, network/security events | TimescaleDB hypertables (same Postgres instance) | High write volume, queried by time range — exactly what hypertables are for; no second database to operate |
| Agent traces (input/output per agent call) | PostgreSQL, one table per agent type, foreign-keyed to incident | Needed for independent agent testing (Section 3, Risk 4) and for the dashboard's Agent Activity view |
| Blockchain outbox + confirmed transaction IDs | PostgreSQL table, polled by a worker | The async bridge described in Section 7, step 13 |
| On-chain provenance records | Hyperledger Fabric ledger | Only the 6 event types from Section 3's Risk 7 resolution; hashes and metadata only, never raw telemetry or patient data |
| Trained model artifacts | Filesystem (`experiments/models/`), versioned by filename + a metadata JSON, not in git | Large binary files don't belong in the repo; `datasets/` and `experiments/models/` are gitignored, with download/training scripts committed instead |
| Raw dataset files (CICIoMT2024, WUSTL-EHMS) | Filesystem, gitignored | Brief explicitly forbids committing huge datasets |

No document store (MongoDB) and no separate graph database at this stage — the brief warns against introducing unnecessary databases, and nothing in Phase 1–8 needs either. If the agent-trace schemas turn out to need fully free-form nested structure that fights a relational shape, Postgres's native `JSONB` columns are the first thing to reach for before adding a new database system.

## 9. IoMT simulator architecture

Each device (Infusion Pump, Ventilator, ECG Monitor) is a state machine, not a static record: it has an operational state (e.g. `idle`, `active`, `alarm`, `isolated`), clinical attributes (`criticality: low|medium|high`, `patient_dependency: bool`, synthetic `patient_id`), and a telemetry generator that emits plausible readings at a configurable interval (drip rate for the pump, respiratory rate/pressure for the ventilator, heart rate/SpO2 for the monitor) with realistic noise — not random numbers, since detection-engine evaluation is only meaningful against telemetry that looks like a real device.

A separate `ScenarioRunner` injects controlled attack scenarios (e.g. "spoof a command to the ventilator at t=30s") by mutating a device's network-event stream in a scripted, reproducible way — same scenario, same seed, same sequence of events every run, which is what Section 17's deterministic test scenarios and Section 18's experiments both depend on.

The simulator exposes its device registry and current state through the same `get_device_state` tool the Healthcare Context Agent calls (Section 13's AI tool list) — there is one source of truth for "is this device patient-dependent right now," not a duplicated copy in the agent layer.

Explicitly out of scope for Phase 2: wearable sensors (brief marks these optional), any real hardware/protocol integration, and any attack that isn't one of the categories selected in Section 10.

## 10. Cybersecurity detection architecture

**Threat model scope for Phase 3** (narrowed from the brief's full candidate list, per its own instruction not to implement every attack just because it's listed): DoS/DDoS floods, reconnaissance/port scanning, MQTT-based attacks, and spoofing — the categories CICIoMT2024 actually labels with enough samples per class to train on, plus MITM spoofing/injection from WUSTL-EHMS. Malware/ransomware behavior and ARP spoofing specifically are deferred — no dataset candidate reviewed so far labels them with adequate sample sizes.

**Baseline-first model strategy:** start with Random Forest and XGBoost on CICIoMT2024's extracted flow features — these are the standard, well-cited baselines for this dataset in the 2024–2025 literature, not an arbitrary pick. Report accuracy, precision, recall, F1, and false-positive rate per attack class before considering a deep-learning model (e.g. an LSTM or a transformer on raw PCAP sequences). Class imbalance (benign + MQTT connect-flood traffic dominate the dataset) is handled with class weighting or SMOTE as a documented experimental step, not silently.

**Output contract:** the detection engine never emits a bare label. Every detection is a structured `DetectionEvent {device_id, attack_type, confidence: float, severity_hint, timestamp, evidence_ref}` — this is the one piece of structured evidence the Investigation Agent is allowed to treat as ground truth (Section 26 of the brief: agents must not invent security evidence).

**Training/runtime split:** the model is trained offline against dataset files (Section 6's `experiments/` directory) and the trained artifact is loaded at runtime by the live detection service, which scores the simulator's live event stream (Section 3's Risk 6 resolution). Retraining is a deliberate, versioned step — never silent online learning.

## 11. Agentic AI architecture

All five agents from the brief are adopted, each as its own backend module with its own input schema, output schema, tool allowlist, and a persisted trace record (Section 3, Risk 4). None of them hold write/execute tools — only the Response Orchestrator (L7) does.

| Agent | Input | Tools (read-only) | Output schema |
| --- | --- | --- | --- |
| Investigation | `incident_id` | `get_logs`, `get_network_events`, `get_telemetry`, `get_device_state` | `InvestigationReport {evidence, timeline, affected_devices, observations, confidence}` |
| Threat Reasoning | `InvestigationReport` | `get_incident` (prior incidents on same device, for propagation context) | `ThreatAssessment {attack_type, severity, confidence, propagation_risk, reasoning_summary}` |
| Healthcare Context | `incident_id`, `affected_devices` | `get_device_state` | `ClinicalContext {device_criticality, patient_dependency, clinical_impact_level, safety_constraints}` |
| Response Planning | `ThreatAssessment`, `ClinicalContext`, `RiskScore` | `evaluate_policy` (read-only check, not execution — "would this be auto-approved") | `ProposedResponse {candidate_actions, security_benefit, clinical_impact, recommended_action, rationale}` |
| Recovery Verification | `incident_id`, executed `response_id` | `get_device_state`, `get_network_events` | `RecoveryResult {containment_verified, residual_threats, recovery_succeeded, reinvestigation_required}` |

**Model abstraction:** an `LLMClient` interface (`generate_structured(prompt, output_schema) -> T`) that each agent calls through — concretely, every agent's LLM call is immediately validated against its Pydantic output schema; a response that fails validation is retried once with the validation error appended, then surfaces as an agent failure rather than being passed downstream unvalidated. This is the mechanical enforcement of the brief's Section 26 requirement (observed fact vs. inference vs. recommendation) — the schema fields themselves separate these (e.g. `evidence` vs. `observations` vs. `recommended_action`).

**Failure handling:** an agent that can't produce a valid structured output after retry marks the incident `investigation_stalled` (or the equivalent per stage) and surfaces it on the dashboard rather than guessing. The closed loop does not silently proceed on bad agent output.

**What's deliberately not decided yet:** the orchestration mechanism between agents (a hand-rolled async pipeline vs. a framework like LangGraph) and which concrete LLM backend to call first. Both are Phase 4 decisions, made after the schemas above are implemented and testable against mocked LLM responses — committing to an orchestration framework before the schemas exist risks shaping the schemas around the framework's constraints instead of the problem.

## 12. Patient-aware dual-risk engine architecture

The interface is fixed now; the function behind it is not (Section 3, Risk 5 resolution).

```python
class RiskModel(Protocol):
    def calculate_risk(
        self,
        threat: ThreatAssessment,
        context: ClinicalContext,
        candidate_responses: list[CandidateAction],
    ) -> RiskScore: ...
```

`RiskScore` carries `cyber_risk: float`, `clinical_risk: float`, and a `response_impact: dict[action_id, float]` — one impact estimate per candidate action, because "shut down" and "isolate network segment" have different clinical impact on the same device, and the Policy Engine needs to compare them, not just see one aggregate number.

**v0 implementation — `RuleBasedRiskModel`:** an explicit, documented table, not a trained model. Example rule: `device.criticality == HIGH and device.patient_dependency and action.category == SHUTDOWN → response_impact = CRITICAL` regardless of `cyber_risk`. Every rule is a named, testable function so Section 17's Scenario B (ventilator compromised, patient-dependent) has a deterministic expected outcome to test against. This is intentionally simple: it is auditable, explainable on the dashboard (brief's Section 10 requires an "explanation" field), and gives later work something concrete to beat.

**What is explicitly deferred:** the actual mathematical form of `Decision = f(cyber_risk, clinical_risk, response_impact)` — whether it ends up as a weighted sum, a learned classifier, a multi-criteria decision rule, or something else is a Phase 5 research question, answered with literature review and sensitivity analysis per the brief's Section 3, not guessed now. The `RiskModel` interface is what makes swapping v0 for a v1 model later a config change, not an API rewrite.

## 13. Safety / policy engine (controlled autonomy)

The Policy Engine is a deterministic service with no LLM call in it anywhere — this is the structural enforcement of "the Agentic AI must never bypass the safety/policy engine." It is the only service that reads a `RiskScore` + `ProposedResponse` and decides routing:

- **Autonomous execution allowed:** `response_impact <= LOW` for the chosen action, regardless of `cyber_risk` (e.g. rotating credentials on a non-critical device).
- **Autonomous execution allowed only if policy conditions hold:** `response_impact == MEDIUM` and `device.patient_dependency == False` (e.g. isolating a non-critical device's network segment).
- **Human approval required:** `response_impact >= HIGH`, or `device.patient_dependency == True` and the action category is in `{SHUTDOWN, ISOLATE_CRITICAL}` — unconditionally, regardless of how severe the cyber threat is. This is the literal implementation of the brief's "most secure cyber response is not always the safest clinical response" principle.

Every policy decision is logged with the specific rule that fired (`policy_rule_id`), not just the outcome — required for both the dashboard's explanation field and for Section 18's "unsafe response rate" evaluation metric to mean anything. The Policy Engine's rule table lives in `backend/app/policy_engine/rules.py` as explicit, reviewable code (not a config file an LLM could influence, and not a black-box model) — given the brief's emphasis on this layer being authoritative, it should be the easiest part of the system to audit by reading it.

## 14. Blockchain provenance architecture

**Network:** Fabric's `test-network` sample, two organizations (Hospital, SecurityOps) plus an orderer, Raft consensus, run via the existing Docker Compose sample scripts rather than a hand-built multi-org deployment (Section 3 decision). A third `Audit` org is a plausible Phase 8 addition once the two-org network is proven, not a Phase 8 requirement.

**Chaincode operations** (brief's candidate list, unchanged as names): `recordIncident`, `recordDecision`, `recordApproval`, `recordResponse`, `recordRecovery`, `verifyEvidence`. Each takes a struct of metadata + a hash, never raw content:

```
recordIncident(incident_id, device_id, attack_type, evidence_hash, timestamp)
recordDecision(incident_id, risk_score_hash, policy_rule_id, recommended_action)
recordApproval(incident_id, approver_identity, decision, timestamp)
recordResponse(incident_id, action_taken, executed_by, timestamp)
recordRecovery(incident_id, recovery_verified, residual_threats_hash)
verifyEvidence(evidence_hash) -> bool   # checks a hash against what's on-chain
```

**Off-chain/on-chain link:** every off-chain record (the Postgres `incidents`, `decisions`, etc. tables) carries a nullable `chain_tx_id` column, populated once the outbox worker (Section 7, step 13) confirms the transaction. A record with `chain_tx_id IS NULL` means "not yet committed," visible as a pending-provenance state on the dashboard — never silently hidden.

**What never touches the chain:** raw telemetry, raw logs, patient identifiers (even synthetic ones), full agent reasoning text. Only hashes and the structured metadata above.

## 15. Backend API architecture

FastAPI routers grouped by resource, matching the brief's list: `/devices`, `/telemetry`, `/events`, `/incidents`, `/detections`, `/risk-assessments`, `/agents`, `/responses/proposed`, `/responses/executed`, `/recovery`, `/blockchain/audit`, `/health`. Each router calls a service-layer function, never the database directly; the service layer calls a repository per aggregate (brief's explicit requirement). Every request/response body is a Pydantic schema — no raw dicts crossing the API boundary.

Authentication/authorization is a Phase 9 concern, not Phase 1, but the schema and dependency-injection pattern for it (a `get_current_user` FastAPI dependency, role-based checks for who can approve a high-impact response) is designed now so it isn't retrofitted. Structured logging (one log line per request with `incident_id` correlation where applicable) and configuration via environment variables (never hardcoded hosts/ports/secrets) are Phase 1 foundation work, built before any of the resource routers above.

## 16. Frontend / SOC dashboard architecture

React + TypeScript, organized around the brief's 14 sections as route-level views sharing a common incident-detail component (since sections 4–14 — Incident Details through Blockchain Audit — are really one incident's full lifecycle viewed through different lenses, not 11 separate pages). The central novelty requirement ("patient-aware decision should be visually obvious") means the incident-detail view's layout puts cyber risk and clinical risk side by side as comparable, equally-weighted panels feeding into one visible decision panel — not cyber risk as the main event with clinical context as a footnote.

The Agent Activity panel reads directly from the agent-trace table (Section 11), so it shows what each agent actually received and produced for this incident, not a narrated summary — this is where "do not fabricate completion" (brief Section 32) applies to the UI too: an agent that hasn't run for this incident shows as not-run, not blank.

Phase 10 builds this; Phase 1 does not touch the frontend beyond scaffolding an empty Vite project so the directory exists and the toolchain is proven to run.

## 17. Testing strategy

Unit tests live beside their module (`backend/app/risk_engine/tests/`) and run against mocked dependencies — the Policy Engine's tests never spin up a real agent or LLM call. Integration tests in top-level `tests/` cover real cross-module paths (detection → incident creation, for instance) against a real test database. End-to-end tests run the two deterministic scenarios the brief specifies almost verbatim, because they exercise exactly the research claim:

**Scenario A — non-critical device compromised:** a simulated infusion pump (criticality=low, patient\_dependency=false) hit with a scripted DoS scenario. Expected: detection fires, risk assessed, Policy Engine auto-approves network isolation, Response Orchestrator executes it, Recovery Agent verifies containment, provenance recorded on-chain. Assertion: no human-approval step was required, and the chosen action was not a shutdown.

**Scenario B — patient-dependent ventilator compromised:** a simulated ventilator (criticality=high, patient\_dependency=true) hit with a scripted command-injection scenario. Expected: Healthcare Context Agent correctly flags high clinical impact, Policy Engine forces `requires_human_approval=true` even though the Threat Reasoning Agent rates cyber severity as critical, a safer non-shutdown action is proposed, and the incident blocks on approval rather than auto-executing. Assertion: the system never autonomously shuts down a patient-dependent, high-criticality device, regardless of attack severity — this is the one assertion that most directly tests the central research claim, so it gets the most scrutiny of any test in the suite.

All scenario tests run against the deterministic `ScenarioRunner` (Section 9) with a fixed seed — same inputs, same outcome, every run, which is also what makes them usable later as the basis for Section 18's experiments rather than one-off checks.

## 18. Research experiment and evaluation strategy

The brief's five-system baseline progression (detection-only → detection + fixed response → detection + agentic AI → detection + risk engine → full patient-aware system) is adopted as-is — it is exactly the right shape for isolating what the patient-aware layer contributes, which is the actual research question. Ablations (without healthcare context, without clinical criticality, without response-impact assessment, without agentic AI, without blockchain, without controlled autonomy, without recovery verification) follow the same pattern: each is the full system with one component's output replaced by a fixed/null value, not a separately built system.

Metrics are implemented as they become measurable, not stubbed with placeholder numbers: cybersecurity metrics (accuracy, precision, recall, F1, false-positive rate) become real once Phase 3's detection engine exists against CICIoMT2024's held-out test split; patient-safety metrics (unsafe-response rate, unnecessary-isolation rate) become real once Phase 5–6 exist and Scenario B-style tests can be run at scale across many randomized scenario parameters, not just the two fixed scenarios in Section 17. No number is reported in `docs/` or anywhere else until the experiment that produces it has actually run — the brief's Section 32 ("do not fabricate completion") applies to metrics as much as to code status.

## 19. Development phases

The brief's 16 phases (0–15) are adopted unchanged — they already match the natural dependency order (you can't build the risk engine before the agents that feed it, can't build agents before the detection engine that triggers them). Phase gates below are what each phase must demonstrably produce before the next one starts, not just the name.

| Phase | Gate to move on |
| --- | --- |
| 0 — Architecture | This document, reviewed and approved |
| 1 — Foundation | `docker compose up` runs an empty FastAPI app that responds on `/health`; tests pass; pushed to GitHub |
| 2 — IoMT simulator | Three devices produce telemetry + a scripted attack scenario deterministically, with tests |
| 3 — Detection engine | A trained model with measured (not assumed) precision/recall on a held-out CICIoMT2024 split |
| 4 — Agentic investigation/reasoning | All 5 agent schemas implemented and unit-tested against mocked LLM responses |
| 5 — Dual-risk engine | `RuleBasedRiskModel` passes Scenario A and B from Section 17 |
| 6 — Safety policy + response orchestration | Policy Engine's rule table is reviewable code with 100% of its branches covered by tests |
| 7 — Recovery + verification | The re-investigation loop (Section 7, step 12) actually re-opens an incident in an integration test |
| 8 — Hyperledger Fabric provenance | `recordIncident` through `verifyEvidence` work against the running test-network, end to end |
| 9 — Backend integration | All resource routers from Section 15 exist and are covered by API tests |
| 10 — SOC dashboard | One incident's full lifecycle is viewable and the dual-risk panel is visually distinct, per Section 16 |
| 11 — End-to-end integration | Scenario A and B run through the real UI, not just backend tests |
| 12 — Testing + hardening | Security checklist from the brief's Section 16 is verified item by item |
| 13 — Experiments + evaluation | At least the detection-only vs. full-system baseline comparison has real, reported numbers |
| 14 — Dockerization + deployment | Full stack (backend, frontend, Fabric network, Postgres) runs from one `docker-compose up` |
| 15 — Final docs + polish | Every claim in `docs/` is checked against what's actually implemented and tested |

**Explicitly not built now, despite being named in the brief:** real multi-org Fabric deployment beyond `test-network`, a trained deep-learning detector (until baselines justify one), wearable-sensor simulation, authentication/authorization (designed for, not implemented, until Phase 9), the frontend beyond an empty scaffold, and any dataset download or processing (Phase 3, with license/accessibility verification first).

## 20. Phase 1 implementation plan

Once this document is approved, Phase 1 produces, in order:

1. Full directory skeleton from Section 6, each directory with a one-line `README.md` stating its purpose — no logic yet.
2. `backend/app/core/`: settings management (pydantic-settings reading from environment variables), structured logging setup, a FastAPI app factory.
3. `backend/app/schemas/`: the Pydantic models already named in this document — `DetectionEvent`, `InvestigationReport`, `ThreatAssessment`, `ClinicalContext`, `ProposedResponse`, `RiskScore`, `RecoveryResult` — as empty-but-typed contracts, not wired to any logic yet. This is intentional: the schemas are the interfaces every later phase builds against, and getting them reviewable now is cheaper than discovering a mismatch in Phase 5.
4. A minimal `/health` endpoint proving the FastAPI app actually runs.
5. `docker-compose.yml` with Postgres + TimescaleDB extension, wired to the backend via `.env` — no Fabric network yet (that's Phase 8).
6. `.env.example`, `.gitignore` (excluding `datasets/`, model artifacts, `.env`, any `*.key`/`*.pem`), `pytest` configuration, a `README.md` at the repo root describing the project and linking to `docs/`.
7. `docs/architecture.md` — a copy of this approved document's decisions, kept in the repo itself so it's versioned alongside the code it governs, not only in this external doc.
8. A CI workflow (`.github/workflows/`) that runs `pytest` and a linter on every push — minimal, but real.
9. Run the test suite locally, confirm it passes, inspect `git status`/`git diff`, commit as `chore: initialize project foundation`, and push to `origin main` — at which point I will report plainly whether the push actually succeeded, including resolving the GitHub push-credential gap flagged in Section 1 if it surfaces.

I will not start any of this until you've reviewed the decisions in Sections 2–3 above, since several of them (the Fabric topology choice, the dataset selection, the rule-based risk model) are exactly the kind of thing that's cheap to change now and expensive to change after Phase 5–8 are built on top of them.
