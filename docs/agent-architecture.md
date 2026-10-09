# Agent architecture

Five specialist agents, a controlled tool registry, and a provider
abstraction. This document specifies the authority boundary and explains
why it is a property of the implementation rather than of the prompts.

---

## 1. The authority boundary

The specification requires that agents "must NEVER bypass deterministic
policy" and must never have "unrestricted shell access" or "arbitrary system
privileges".

**Those are not properties a prompt can deliver.** A prompt is a request. An
instruction not to do something is advice to a probabilistic system, and
"the model was told not to" is not a safety argument a reviewer should
accept. So the boundary is structural:

| Mechanism | What it prevents |
|---|---|
| Fixed per-agent **allowlist** (`frozenset`, set at construction) | Reaching any tool outside the declared set, even if the prompt were rewritten |
| Per-tool **authority class** + per-role **ceiling** | Privilege escalation. Every role tops out at `COMPUTE` |
| Tools are **pure functions over a read-only context** | There is no shell, filesystem, network, `eval` or `__import__` to misuse |
| **Argument schema validation** before dispatch | Malformed or injected arguments reaching code |
| Separate **orchestrator ceiling** | Actuation happening inside agent reasoning rather than after a policy ruling |

### Authority classes

```
READ_ONLY  <  COMPUTE  <  REQUEST_APPROVAL  <  ACTUATE  <  LEDGER_WRITE
└── agents are capped here ──┘ └──── orchestrator only ─────────────┘
```

| Role | Ceiling |
|---|---|
| Investigation | `READ_ONLY` |
| Threat reasoning | `COMPUTE` |
| Healthcare context | `COMPUTE` |
| Response planning | `COMPUTE` |
| Recovery verification | `COMPUTE` |

**Consequence worth stating plainly:** `propose_safe_action`,
`request_human_approval` and `record_provenance` are reachable by **no agent
role**. They are invoked by the orchestrator after the deterministic policy
engine has ruled, and appear on the timeline as a distinct actor. An agent
that attempts one gets `AuthorityViolation`, the run aborts with status
`ABORTED_AUTHORITY`, and the attempt is recorded for the evaluation's
attempted-violation count.

`tests/unit/test_agents.py::TestAuthorityBoundary` asserts all of this by
attempting the violations.

### A deliberate deviation from the specification

The spec names a tool `execute_safe_action`. It is implemented as
**`propose_safe_action`**, because it does not execute — it returns a request
for the policy engine.

The rename is not cosmetic. A tool name that overstates its authority is a
latent hazard: it invites a future contributor to "fix" the mismatch by
making the tool actually actuate, which would make the policy engine
bypassable and destroy the platform's central safety property. A CI test now
rejects any tool name containing `execute`.

---

## 2. The tools

Nineteen tools. Beyond the sixteen named in the specification, three were
added: `get_timeline`, `get_exhausted_actions` and
`evaluate_candidate_actions`.

### Read-only (9)
`get_incident` · `get_device_profile` · `get_device_state` · `get_telemetry` ·
`get_network_events` · `get_security_logs` · `get_attack_evidence` ·
`get_clinical_context` · `get_timeline` · `get_exhausted_actions`

### Compute (5)
`calculate_cyber_risk` · `calculate_clinical_risk` ·
`evaluate_response_impact` · `evaluate_candidate_actions` ·
`evaluate_policy` · `verify_recovery`

These **delegate to the deterministic engines and return their results
verbatim**. There is no tool that writes a risk score. An agent can read a
score and reason about it; it cannot produce or alter one.

### Privileged — orchestrator only (3)
`request_human_approval` · `propose_safe_action` · `record_provenance`

### Two implementation details that matter for validity

**Telemetry strips the simulator's truth channel.** `get_telemetry` removes
every `truth_*` field, so an agent sees what the device *reports* — exactly
what a clinician sees. Under the telemetry-spoofing scenario the reported
SpO2 reads 97% while the patient is at 74%. Leaving the truth channel
visible would make the spoofing scenario trivially solvable and the agent's
performance on it meaningless. The payload carries an explicit note that
reported values may be spoofed.

**Evidence may carry identity; the feature matrix may not.** Source IPs and
MACs are available to agents for investigation, because that is what
investigation means. They are banned from the detection feature matrix
(`cybersecurity/schema.py:FORBIDDEN_FEATURES`) because there they leak. The
two uses are kept deliberately separate.

---

## 3. A measured design error

The response-planning agent originally evaluated candidate actions one per
tool call: 4 context tools + 13 candidates = **17 calls against a 16-call
budget**. It timed out having produced no plan at all, while the other four
agents succeeded.

The tempting fix is to raise the budget. That would have hidden the real
problem: **a per-candidate round trip is the wrong granularity for a
comparison that is inherently over a set.** `evaluate_candidate_actions`
now returns the whole ranked comparison in one call, with each row marked
`admissible` or not.

Result: planning dropped from 17 calls (timeout, no output) to **5 calls**
(success). The budget was also raised to 24 for headroom, but that was the
secondary change.

This is recorded because the agent-latency and tool-call-count metrics in
the evaluation are only meaningful if the tool granularity is sane.

---

## 4. Provider abstraction

Two reasons it exists rather than a direct API call.

**Reproducibility.** An experiment whose results depend on a hosted model's
behaviour at a particular moment is not reproducible, and a paper reporting
such numbers cannot be checked. The `DeterministicProvider` is a rule-based
planner — no model, no network, no API key — that makes the whole closed
loop runnable offline with byte-identical output for a given seed.

**Honesty about what the agents contribute.** Running with the deterministic
provider *is* an ablation: it isolates how much behaviour comes from the
orchestration and deterministic engines versus from the language model. That
comparison belongs in the paper, and is only possible if both can run.

The deterministic provider is **not presented as a language model**. Every
`AgentRunRecord` carries `provider` and `model`, and the evaluation labels
every run with what produced it.

```
AGENT_LLM_PROVIDER=deterministic   # default: offline, reproducible
AGENT_LLM_PROVIDER=anthropic       # requires ANTHROPIC_API_KEY
```

Results obtained with a real provider are reported **separately**, with model
version, temperature, seeds and across-run variance.

---

## 5. Output validation

Every agent output is validated against a Pydantic schema before acceptance.
Three guards matter:

1. **Every finding must declare its epistemic status** — `observed_fact`,
   `inference` or `recommendation`. A finding without one is rejected. This
   is how the separation survives into the audit trail.
2. **`evidence_verified` cannot exceed `evidence_reviewed`** — an agent
   cannot claim to have verified evidence it did not look at.
3. **A candidate list may not contain an action classified `unsafe`** — an
   agent cannot propose what the risk engine has already ruled out.

Invalid output is retried up to `max_retries` with the validation error fed
back. Persistent failure yields `VALIDATION_FAILED` and the output is
**discarded, never passed downstream** — malformed agent output must not
reach the risk engine.

---

## 6. Failure semantics

| Condition | Status | Behaviour |
|---|---|---|
| Tool returns an error | run continues | the error becomes an observation the agent can work around |
| Authority violation | `ABORTED_AUTHORITY` | immediate abort, recorded, never retried |
| Output fails validation | `VALIDATION_FAILED` after retries | output discarded |
| Tool-call or time budget exceeded | `TIMED_OUT` | partial record kept |
| Provider raises | `FAILED` | recorded, not propagated |

An agent cannot stall an incident indefinitely, and a failing agent degrades
the pipeline rather than halting it — the deterministic engines still have
the detection and the device context.

---

## 7. Observed behaviour

Deterministic provider, all three mandated scenarios, full pipeline:

| Scenario | Planning recommends | Approval | Rejected |
|---|---|---|---|
| **S2** ventilator, life-critical | `rotate_credentials` | **required** | 5 unsafe |
| **S1** workstation, ransomware | `isolate_network_segment` | **not required** | 0 |
| **S3** re-plan after failure | `rotate_credentials` | required | `block_source_traffic` (already attempted) |

All five agents succeed on all three, in 4–8 tool calls each. S1 producing
*autonomous* containment and S2 producing an approval requirement, from the
same code and prompts, is the controlled-autonomy behaviour the platform
claims.

---

## 8. Threats to validity

1. **The deterministic provider is not a language model.** Results from it
   measure the orchestration, not an LLM. Labelled as such everywhere.
2. **Agent-accuracy metrics depend on the provider.** Reported per provider,
   never pooled.
3. **Prompt sensitivity is unmeasured.** Real-provider results will vary
   with prompt wording; the structural guarantees will not, which is the
   argument for putting safety in the registry rather than the prompt.
4. **The deterministic provider's plan is hand-written.** It encodes a
   sensible evidence-gathering order, which is a design choice, not a
   finding. An LLM may gather differently; that difference is the ablation.
