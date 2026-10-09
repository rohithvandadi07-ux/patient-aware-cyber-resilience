# Controlled-autonomy policy, response orchestration and recovery

> **Simulation policy, not clinical guidance.** Every rule and threshold here
> is a research parameter governing a simulated environment. Nothing in this
> document is a standard of care or advice about real devices.

---

## 1. The policy engine

Deterministic and authoritative. Takes a candidate action plus the
authoritative risk results, returns exactly one verdict: `AUTO_ALLOWED`,
`APPROVAL_REQUIRED` or `DENIED`.

Four properties are enforced at load time, so a malformed policy fails
loudly rather than behaving unsafely:

| Property | Enforcement |
|---|---|
| **Total** — every input yields a verdict | the last rule must have empty conditions |
| **Fall-through is not permissive** | the catch-all may not be `auto_allowed` |
| **Unsafe is denied before anything is allowed** | a denial of `impact_class: unsafe` must precede the first `auto_allowed` rule |
| **Rule language is small enough to audit** | an unknown condition key is a load error, not a silently-ignored condition |

### Denial is not escalation

An action classified `UNSAFE` is **denied**, not forwarded for approval.

This is a deliberate design decision with a reason: asking a human to
authorise something the system has already determined is unsafe converts a
safety judgement into a liability transfer, and a clinician under time
pressure is the wrong place to relocate it. If the system knows an action
will harm the patient, the correct behaviour is to refuse and offer
something else — not to ask permission.

### Observed verdict table

Same actions, same policy, different device context:

| Action | Workstation (`NON_CLINICAL`, clinical risk 0.14) | Ventilator (`LIFE_SUSTAINING`, clinical risk 1.00) |
|---|---|---|
| `monitor_only` | auto-allowed | auto-allowed |
| `block_source_traffic` | auto-allowed | auto-allowed |
| `rotate_credentials` | auto-allowed | **approval required** |
| `quarantine_device` | auto-allowed | **denied** |
| `isolate_network_segment` | auto-allowed | **denied** |
| `shutdown_device` | approval required *(irreversible)* | **denied** |

Every verdict records the rule that produced it, so an autonomous action is
attributable to a specific published rule rather than to an opaque score.

### The autonomy budget

An auto-allowed action still escalates to approval once
`max_autonomous_actions_per_incident` is spent. A loop that keeps acting
without converging is exactly the case where a human should be looking at
it, and an unbounded autonomous loop is the failure mode that makes
"controlled autonomy" meaningless.

### Approval timeout

`on_timeout: deny`. An unanswered approval request becomes a **rejection**,
never consent. A system in which silence authorises action is not
human-in-the-loop.

---

## 2. Response orchestration

```
PROPOSED → POLICY_CHECK → {DENIED | APPROVAL_REQUIRED | AUTO_ALLOWED}
         → APPROVED → EXECUTING → {EXECUTED | FAILED}
         → RECOVERY_CHECK → {RECOVERED | RESIDUAL_RISK}
         → {RESOLVED | REINVESTIGATION}
```

Three structural invariants, asserted by `validate_response_machine()`:

1. **`EXECUTING` is reachable only from `AUTO_ALLOWED` or `APPROVED`.** There
   is no path to actuation that skips a permitting verdict.
2. **`DENIED` and `REJECTED` are terminal.** A refused response cannot be
   revived.
3. **`RESOLVED` is reachable only from `RECOVERED`.** Execution alone cannot
   close a response.

### Policy is unskippable

`execute()` refuses — raising `UnauthorisedExecution` rather than returning
a failure — when the response has no policy verdict, the verdict was
`DENIED`, approval is pending, rejected or expired, or the state is not
`AUTO_ALLOWED`/`APPROVED`.

Raising rather than returning is deliberate: reaching actuation without
permission is a *programming error in the orchestration*, not a runtime
condition to handle gracefully. It should crash a test, not log a warning.

Combined with the agent layer holding no actuation tool
([`agent-architecture.md`](agent-architecture.md)), there is exactly **one
code path** from decision to effect, and it passes through the policy
engine. Six tests assert the actuator is never called on any refused path.

---

## 3. Recovery verification

Recovery is mandatory — the incident lifecycle makes `RESOLVED` reachable
only through `RECOVERING`.

Seven deterministic checks. Four are mandatory: failing any cannot be offset
by passing the others.

| Check | Why it exists |
|---|---|
| `response_executed` | the actuator reported success |
| **`anomaly_cleared`** | the triggering condition is gone. *Execution is not recovery* — conflating them is how a platform closes an incident while the attacker is still present |
| **`attack_mechanism_severed`** | the specific capability the attack depended on is gone |
| `device_service_available` | the device is reachable and serving |
| `network_contained` | flow rate is near baseline |
| **`no_new_fault_introduced`** | the response did not itself break the device |
| **`therapy_continuity`** | therapy still reaches a patient who depends on it |

`no_new_fault_introduced` and `therapy_continuity` are what make this
patient-aware recovery rather than generic incident closure. A containment
action that stops the attack and interrupts therapy has **not** succeeded,
and the engine says so explicitly rather than leaving it to judgement.

Residual risk is a *weighted* combination, not a failure fraction, because
the checks are not equally informative — a still-active attack mechanism
matters far more than a missing flow measurement. A still-active attack
floors residual risk at 0.60 regardless of what else passed.

### The asymmetry mandated scenario 3 depends on

`MECHANISM_SEVERED_BY` encodes which actions actually remove which
capabilities. The load-bearing entry:

```python
AttackType.UNAUTHORIZED_ACCESS: {
    REVOKE_SESSION, ROTATE_CREDENTIALS, QUARANTINE_DEVICE,
    ISOLATE_NETWORK_SEGMENT,
}   # NOT block_source_traffic
```

An attacker holding a valid session is not removed by blocking their
traffic — they already have the session. So blocking executes perfectly and
still fails recovery, which is what makes the re-planning loop principled
rather than scripted.

---

## 4. Mandated scenario 3, end to end

Measured, with the deterministic provider:

```
ATTEMPT 1: block_source_traffic   policy=auto_allowed → recovery=residual_risk (0.60)
             FAIL anomaly_cleared
             FAIL attack_mechanism_severed
                  "block_source_traffic does not sever the mechanism
                   unauthorized_access depends on"
ATTEMPT 2: rotate_credentials     policy=auto_allowed → recovery=RECOVERED (0.00)

=> RESOLVED after 2 attempts. Exhausted: ['block_source_traffic']
```

The loop detects failure, excludes the failed action, selects a
*mechanism-appropriate* alternative, and converges. The first action is
never retried.

---

## 5. A measured defect: two layers disagreeing

The first run of this scenario did **not** converge. Attempt 2
(`rotate_credentials`) also failed recovery, reporting the attack as still
active.

The recovery engine was right; the **simulator** was wrong. The infusion
pump's control handler cleared `MALICIOUS_COMMAND` on credential rotation
but left `UNAUTHORIZED_ACCESS` — the session itself — installed. So the
simulator claimed rotating credentials does not end a session, while
`MECHANISM_SEVERED_BY` claimed it does.

Two layers disagreeing about a mechanism makes every recovery metric
meaningless, and the symptom pointed at the wrong layer. The fix moved
session invalidation into the device **base class**, so all devices behave
consistently, and added a test that cross-checks the simulator against
`MECHANISM_SEVERED_BY` for all four session-based attack types on all four
device classes.

This is the class of bug that is invisible in unit tests of either layer
alone and only appears when the loop is run end to end.

---

## 6. Ablation support

| Ablation | Mechanism |
|---|---|
| Without controlled autonomy | `policy.with_autonomy_disabled()` — every action requires approval |
| Without recovery verification | skip the recovery engine; responses close on execution |
| Fixed response | bypass the risk engine's selection; always use one action |
| Cyber-only decision | `engine.decide(patient_aware=False)` |

All four run through the same code paths, so an ablation differs only in the
component removed rather than in which implementation is exercised.

---

## 7. Threats to validity

1. **Thresholds are parameters.** Swept in the sensitivity analysis; the
   *ordering* of rules is the defensible part, not the exact numbers.
2. **`MECHANISM_SEVERED_BY` is engineering judgement.** It encodes
   defensible claims (a session survives traffic blocking; firmware tamper
   survives a restart) but is not empirically calibrated against real
   devices.
3. **Recovery checks are simulator observations.** A deployed system would
   infer attack persistence from telemetry rather than reading ground truth.
   The `active_attack_types` field is explicitly labelled as simulation-only.
4. **Approval is scripted in experiments.** Real human approval latency and
   error rates are not modelled; human-approval *rate* is reported, not
   human decision quality.
