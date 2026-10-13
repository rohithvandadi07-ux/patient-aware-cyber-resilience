# Threat model

This document describes the threat model actually implemented by the code in
this repository today — not the full candidate attack surface of a real
hospital network. It is scoped the same way `docs/architecture.md` §10 scopes
the detection engine: narrowed to what the system actually defends against,
not every threat healthcare IoMT could face in principle. Where the system's
real boundaries are narrower than a reader might expect, that is stated
directly rather than implied away.

## 1. Assets being protected

Read from `backend/app/iomt_simulator/hospital.py` (`build_default_fleet`)
and the schemas each layer actually passes around:

| Asset | What it is in this system | Where |
| --- | --- | --- |
| Simulated medical devices | An infusion pump, a ventilator, and an ECG/patient monitor — each a `SimulatedDevice` state machine with `criticality`, `patient_dependency`, and an operational/network state | `backend/app/iomt_simulator/device.py`, `hospital.py` |
| Device telemetry | Synthetic vital-sign/operational readings generated per tick | `backend/app/iomt_simulator/telemetry.py` |
| Network/security events | The event stream a scenario run produces, including attack injections | `backend/app/schemas/events.py` |
| Incident and decision records | `Incident`, `DetectionEvent`, agent traces, `RiskScore`, `PolicyDecision`, `ExecutedResponse`, `RecoveryResult` | `backend/app/schemas/` |
| Blockchain provenance | Hashes/metadata of the above six event types, on the Fabric ledger | `backend/app/schemas/blockchain.py` |
| The trained detection model artifact | `experiments/models/*.joblib` | `backend/app/cybersecurity/` |

**What is explicitly not a real asset here, because nothing real exists
behind it:** no real patient exists (`patient_id` is synthetic), no real
clinical data is processed, and no real IoMT protocol (MQTT, DICOM, HL7,
BLE) is spoken over a real network — everything above is simulated in a
single backend process. The threat model below is therefore a threat model
*for the simulation and the decision pipeline around it*, which is also
exactly what this project's research question (patient-aware response
decisioning) needs a threat model for — not a threat model for a production
hospital network, which this system has never claimed to be.

## 2. Trust boundaries

Boundaries as the code actually draws them, not as a generic IoMT diagram
would draw them:

1. **Attacker → simulated network event stream.** The only way an "attack"
   enters this system at all is as a `NetworkEvent` tagged
   `is_attack_injection=True`, produced by `ScenarioRunner`
   (`backend/app/iomt_simulator/scenario.py`) or, for the trained-model path,
   as a labeled row of `synthetic_data.py`'s synthetic dataset. There is no
   real network interface, no real packet capture, and no real device
   firmware anywhere in this codebase for an attacker to actually reach —
   this boundary is a function call and a dataset row, not a wire.
2. **Detection engine → Incident.** `DetectionService.score_window`
   (`backend/app/cybersecurity/detection_service.py`) is the only thing that
   turns a scored event window into a `DetectionEvent`, and only
   `/detections/run-scenario` and `/incidents` (`POST`) turn that into an
   `Incident`. Everything downstream of this boundary treats `DetectionEvent`
   fields (`evidence_ref`, `confidence`, `attack_type`) as ground truth it
   must not re-derive or embellish (architecture spec §26, enforced by the
   agents' own schema field separation — see §4 below).
3. **Agents → everything else.** Every agent (`backend/app/agents/*.py`)
   reads only through `AgentToolkit` (`backend/app/agents/tools.py`), a
   fixed, read-only method list. No agent module imports a repository,
   registry, or orchestrator directly, and `AgentToolkit` itself has no
   `execute_*` method for any agent to call — confirmed by reading
   `tools.py` in full: every method name is a `get_*`/`evaluate_*`
   (read/check) call.
4. **Policy Engine → execution.** `ResponseOrchestrator.execute`
   (`backend/app/response_engine/orchestrator.py`) is, by its own module
   docstring, "the only function anywhere in this codebase that calls a
   `SimulatedDevice` mutation method on the strength of a `PolicyDecision`."
   Nothing upstream of the Policy Engine (`backend/app/policy_engine/
   engine.py`) can reach a device mutation directly.
5. **Off-chain → on-chain.** Every write to Fabric goes through the outbox
   (`backend/app/blockchain/outbox.py`) and only the six named operations
   (`recordIncident`, `recordDecision`, `recordApproval`, `recordResponse`,
   `recordRecovery`, `verifyEvidence`) ever cross it, carrying only hashes
   and structured metadata (re-verified in `docs/security-checklist.md` §4)
   — raw telemetry, logs, and agent reasoning text never cross this
   boundary.
6. **HTTP client → backend.** Every one of the 12 routers under
   `backend/app/api/` except `/health` now resolves a real auth dependency
   (`backend/app/core/auth.py`'s `get_current_principal`, post-Phase-15) —
   but it defaults to disabled (`Settings.auth_enabled=False`), so an
   unconfigured deployment is exactly as open as described below until
   `AUTH_ENABLED=true` plus real `API_KEYS` are set. With auth enabled,
   approving/executing a response and auto-approving an investigation cycle
   additionally require the `approver` role (see `docs/security-checklist.md`
   §6 for the real test coverage).

## 3. Attacker profiles considered

The architecture spec (§19, referencing the master plan's attacker
taxonomy) names four attacker categories. Here is what each one actually
maps to in the running system, and where the mapping is honest about not
reaching further:

**External network attacker (the one actually modeled).** This is what
`ScenarioRunner`'s `AttackInjection` and the CICIoMT2024-shaped synthetic
dataset both represent: someone outside the hospital network sending
malicious traffic at a device. Concretely, the `AttackCategory` enum
(`backend/app/schemas/enums.py`) is the complete list of attacker behaviors
this system can detect or reason about: `DOS`, `DDOS`, `RECONNAISSANCE`,
`MQTT_BASED`, `SPOOFING`, `MITM_INJECTION`, plus `UNKNOWN` as a catch-all.
Nothing else is a defined attack category anywhere in the schemas — malware/
ransomware behavior and ARP spoofing specifically are named in
`docs/architecture.md` §10 as deferred, and remain so; there is no code path
that labels or scores either.

**Compromised IoMT device (partially modeled, as an effect, not a cause).**
The simulator models a device's *resulting* state after an attack
(`AttackInjection.device_effect`, e.g. `set_network_state("compromised")`
or a mutated telemetry reading for a spoofed command) — so "this ventilator
is now compromised" is a real, assertable state in a scenario. What is not
modeled: a compromised device acting as an attacker itself (e.g. pivoting to
attack other devices, or sending malicious traffic it wasn't scripted to
send). `SimulatedDevice` has no autonomous/adversarial behavior of its own;
it only reflects whatever `AttackInjection` or the scenario script tells it.

**Network-level (on-path) attacker (not modeled as a distinct capability).**
There is no separate "attacker sits between two legitimate parties and
manipulates traffic in flight" simulation distinct from spoofing/injection
events already covered by `SPOOFING`/`MITM_INJECTION`. The WUSTL-EHMS-2020
dataset `docs/architecture.md` names for MITM/injection labels has never been
downloaded in this project (`datasets/LICENSE_NOTES.md`) — only the
synthetic stand-in's `MITM_INJECTION`-labeled rows exist, so this category is
currently real only as a label, not as a distinctly-behaving simulated
attacker.

**Insider misuse (not modeled at all).** There is no user/role model, no
authentication, and therefore no concept of "a legitimate hospital staff
member or SecurityOps operator doing something they shouldn't" anywhere in
this codebase. The closest related concept is the Policy Engine's human-
approval step (`ApprovalRecord`, `backend/app/schemas/response.py`) — but
that record carries only a free-text `approver_identity` string with no
verification behind it (no login, no identity provider, nothing that checks
the string is who it claims). An insider-misuse threat model would need a
real identity/authorization layer first; this is a known, disclosed gap
(see §5 below and `docs/security-checklist.md` §6), not a modeled-and-
mitigated case.

## 4. What the system structurally cannot be tricked into doing

This is the actual, code-enforced containment this project claims, each
claim tied to the specific mechanism that enforces it:

- **An agent's LLM output cannot directly execute anything.** No agent
  module holds an execute-capable tool (verified by reading
  `backend/app/agents/tools.py`'s complete `AgentToolkit` method list — see
  §2.3 above); only `ResponseOrchestrator.execute` can mutate a device, and
  it takes a `PolicyDecision`, never an agent's raw output, as its input.
- **A fabricated/hallucinated finding cannot masquerade as detected
  evidence.** `InvestigationReport.evidence` is built only from real
  `AgentToolkit` tool-call results interpolated into the agent's prompt
  (`investigation.py`'s `_build_prompt`); the schema's own field separation
  (`evidence` vs. `observations` vs. `recommended_action`) is what keeps
  "what the tools actually returned" distinct from "what the agent inferred
  from it," per architecture spec §26 — but this separation is enforced by
  convention in the prompt and schema shape, not by a runtime check that
  `evidence` values are a subset of what the tools returned. A sufficiently
  adversarial LLM backend could still populate `evidence` with invented
  content; nothing downstream currently re-validates that field against the
  toolkit's actual return values.
- **A response that is HIGH-impact or touches a patient-dependent critical
  device cannot auto-execute, regardless of how the cyber-severity fields
  are populated.** This is `PolicyEngine`'s rule table
  (`backend/app/policy_engine/rules.py`), independent of any LLM call
  (`docs/architecture.md` §13: "a deterministic service with no LLM call in
  it anywhere"), and it is the one rule Phase 13's own evaluation
  (`evaluation/phase13_baseline_comparison.md`) measured directly: 0/162
  unsafe autonomous actions on high-stakes real-attack trials for the full
  system, versus 162/162 for the naive baseline.
- **Raw telemetry/logs/patient identifiers cannot reach the blockchain.**
  Only the five `*Provenance` schemas (`backend/app/schemas/blockchain.py`)
  are ever constructed for an outbox write, and each carries only IDs,
  enums, hashes, and timestamps — re-verified field-by-field in
  `docs/security-checklist.md` §4.

## 5. What this threat model does not cover (disclosed gaps, not oversights)

- **Authentication/authorization exists but is off by default.**
  Post-Phase-15: `backend/app/core/auth.py` is real and wired onto every
  route except `/health`, but `Settings.auth_enabled` defaults to `False` —
  an unconfigured deployment is exactly as open as this paragraph used to
  describe unconditionally. A client that can reach the backend process can
  call every endpoint, including `POST /responses/executed` (the one
  endpoint that can mutate simulated device state), **unless**
  `AUTH_ENABLED=true` and real `API_KEYS` are configured (see
  `docs/security-checklist.md` §6). Still disclosed as a real operational
  risk: the default is permissive, and nothing forces a deployer to turn
  auth on.
- **No rate limiting or request-size limiting.** Confirmed absent by grep
  (`docs/security-checklist.md` §5) — a trivial denial-of-service vector
  against the API itself, separate from anything the IoMT simulator models.
- **No real network, no real device firmware, no real IoMT protocol.**
  Every "attack" is a function call or a dataset row, not a packet on a
  wire. A real deployment threat model would need to additionally cover
  physical access, RF/BLE attacks, firmware tampering, and actual protocol
  implementations (MQTT broker misconfiguration, DICOM/HL7 parsing bugs) —
  none of which this codebase implements or could be attacked through, since
  none of it exists here.
- **No multi-tenant or multi-hospital isolation model.** One simulated
  three-device fleet, one process, no tenancy boundary of any kind.
- **The approval identity (`ApprovalRecord.approver_identity`) is an
  unverified string.** There is no mechanism tying it to a real,
  authenticated person. Any insider-misuse or approval-forgery threat model
  is blocked on this gap, not on anything this document can mitigate by
  description.

## 6. Detection and response boundaries, concretely

What "detection" and "response" actually mean in terms of code, so this
threat model doesn't imply more real-time capability than exists:

- **Detection is on-demand, not continuous.** There is no scheduler or
  polling loop; `/detections/run-scenario` runs one fixed, reproducible
  scenario per call (`backend/app/api/detections.py`'s own docstring is
  explicit about this). A later phase could call the same `DetectionService
  .score_window` path from a scheduler without changing it, but nothing in
  this repo currently does.
- **Response execution is synchronous with the API request that triggers
  it**, not an autonomous background loop — `POST /responses/executed` is
  what actually calls `ResponseOrchestrator.execute`; nothing runs this on a
  timer.
- **Recovery verification is also an on-demand `POST`**, not a scheduled
  re-check — `POST /recovery` wraps `RecoveryOrchestrator.process_result`
  on whatever `RecoveryResult` the caller supplies (again, no real LLM
  backend produces one automatically yet).
