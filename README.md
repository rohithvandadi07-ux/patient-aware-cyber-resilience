# Patient-Aware Cyber-Resilience

**A patient-aware, controlled-autonomy cyber-resilience platform for safety-critical healthcare IoMT.**

[![CI](https://github.com/rohithvandadi07-ux/patient-aware-cyber-resilience/actions/workflows/ci.yml/badge.svg)](https://github.com/rohithvandadi07-ux/patient-aware-cyber-resilience/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> **Research software.** This is a simulation platform. It is **not** a medical
> device, is **not** clinically validated, and holds **no** regulatory
> certification. It must never be connected to real medical devices or used to
> inform patient care. All patient data is synthetic.

---

## The problem

Autonomous cyber-defense for hospital networks has a blind spot: it optimises
for security outcomes while treating every asset as interchangeable. But a
ventilator is not a printer.

> **The most secure cyber response is not always the safest clinical response.**

Isolating a compromised ventilator from the network maximally reduces cyber
risk. It may also kill the patient depending on it. A defender that cannot
represent that trade-off is not safe to automate.

## Research question

> How can autonomous cyber-defense protect safety-critical healthcare IoMT
> devices while making response decisions that jointly consider cybersecurity
> risk **and** patient/clinical impact?

## Contribution

**Patient-Aware Dual-Risk Decision Making for Autonomous IoMT Cyber-Defense.**

After detection, the platform jointly evaluates three deterministic, audited
quantities before any action is taken:

| Term | Question it answers |
|---|---|
| **Cyber risk** | How dangerous is this attack? |
| **Clinical risk** | How much does the patient depend on this device right now? |
| **Response impact** | What would *this specific response* cost clinically? |

Conceptually `DecisionRisk = f(CyberRisk, ClinicalCriticality, ResponseImpact)`.
This is a **starting point, not a finished equation** — the implemented
formulation is parameterised, versioned, and justified through sensitivity
analysis and ablation (see [`docs/risk-model.md`](docs/risk-model.md) and
[`docs/experiments.md`](docs/experiments.md)).

Every decision records the **counterfactual**: the action a cyber-risk-only
defender would have taken. Divergence between the two is the contribution,
measured rather than asserted.

## Architecture

```
IoMT DEVICES (simulated smart hospital)
      │  telemetry · network flows · commands · auth · security logs
      ▼
EVENT / TELEMETRY NORMALISATION
      ▼
CYBERSECURITY DETECTION ENGINE ──────► "What is happening?"
      ▼
INCIDENT INTELLIGENCE  (correlation · evidence · timeline · lifecycle)
      ▼
AGENTIC AI  ─────────────────────────► "What does it mean? What are the options?"
   ├─ Investigation Agent          (read-only tools)
   ├─ Threat Reasoning Agent       (no response authority)
   ├─ Healthcare Context Agent     (read-only clinical context)
   ├─ Response Planning Agent      (recommend only)
   └─ Recovery Verification Agent  (may request re-investigation)
      ▼
PATIENT-AWARE DUAL-RISK ENGINE  (deterministic · auditable · AUTHORITATIVE)
   cyber risk  +  clinical risk  +  response impact
      ▼
DETERMINISTIC SAFETY / POLICY ENGINE
   auto-allow │ require human approval │ deny
      ▼
RESPONSE ORCHESTRATOR  (simulated actuation only)
      ▼
RECOVERY VERIFICATION ──── fails ────► RE-INVESTIGATE → RE-PLAN → RE-RESPOND
      ▼
PERMISSIONED BLOCKCHAIN PROVENANCE ──► "Can we prove what we decided, and why?"
      ▼
HEALTHCARE SOC DASHBOARD
```

**Authority boundary (non-negotiable):** the LLM-driven agents investigate,
reason and *recommend*. The deterministic risk and policy engines *decide*. An
agent cannot bypass policy, cannot actuate a denied action, and cannot
overwrite a risk score. This is enforced in the tool registry, not by prompt
instruction.

## Status

Under active continuous build. See [`docs/`](docs/) for component specifications
and the task progression in commit history.

## Quickstart

```bash
git clone https://github.com/rohithvandadi07-ux/patient-aware-cyber-resilience.git
cd patient-aware-cyber-resilience

python3 -m venv .venv && source .venv/bin/activate
make install-dev

cp .env.example .env     # then edit: set AUTH_SECRET_KEY and passwords
make test
make demo                # full closed-loop demonstration
```

Default configuration runs **fully offline**: the deterministic agent provider
needs no API key, and the hash-chained local provenance ledger needs no Fabric
network. Both are swapped to real backends by environment variable.

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Subsystems, dependency rules, data flow |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, trust boundaries, attacker capabilities, scope |
| [`docs/agent-architecture.md`](docs/agent-architecture.md) | Agent contracts, tool registry, authority enforcement |
| [`docs/risk-model.md`](docs/risk-model.md) | Risk formulations, parameters, justification |
| [`docs/policy.md`](docs/policy.md) | Controlled-autonomy policy specification |
| [`docs/iomt-simulator.md`](docs/iomt-simulator.md) | Device state machines, attack injection, determinism |
| [`docs/datasets.md`](docs/datasets.md) | Benchmark dataset survey, licensing, ingestion |
| [`docs/api.md`](docs/api.md) | REST API reference |
| [`docs/blockchain.md`](docs/blockchain.md) | Fabric topology, chaincode, local ledger |
| [`docs/experiments.md`](docs/experiments.md) | Methodology, baselines, ablations, metrics |
| [`docs/reproducibility.md`](docs/reproducibility.md) | Seeds, versions, exact reproduction steps |
| [`docs/security.md`](docs/security.md) | Platform security model |
| [`docs/limitations.md`](docs/limitations.md) | Limitations, ethics, safety boundaries |
| [`docs/deployment.md`](docs/deployment.md) | Local, Compose and Fabric deployment |

## Research integrity

- No metric in this repository is hand-written. Every number is produced by a
  script in `experiments/` and reproducible from a seed.
- Simulator-derived results are labelled as such and never presented as
  benchmark-dataset results.
- No "first-ever" claims are made. The contribution is positioned against
  related work in `docs/`.
- Observed fact, inference and recommendation are structurally separated
  throughout the codebase (`AssertionClass`).

## License

MIT — see [`LICENSE`](LICENSE), including the research software notice.
