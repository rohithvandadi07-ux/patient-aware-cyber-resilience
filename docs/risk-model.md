# The patient-aware dual-risk model

This document specifies the formulation, states what is parameter versus
what is finding, and records the design decisions a reviewer will question.

> **Status of the numbers.** Every coefficient in
> `configs/risk_profile.default.yaml` is a **parameter**, not a result. The
> conceptual starting point from the specification —
> `DecisionRisk = f(CyberRisk, ClinicalCriticality, ResponseImpact)` — is
> instantiated here as one defensible choice of `f`. The sensitivity analysis
> sweeps it and the paper reports how conclusions move.

---

## 1. Structure

Three independent deterministic terms, then a selection rule.

```
                    ┌─────────────────┐
  detection ───────►│   CYBER RISK    │  "how dangerous is this attack?"
                    └─────────────────┘   asset-agnostic
                    ┌─────────────────┐
  device profile ──►│ CLINICAL RISK   │  "how much does the patient
  device state      └─────────────────┘   depend on this device now?"
                    ┌─────────────────┐
  each candidate ──►│ RESPONSE IMPACT │  "what would THIS action cost?"
  + the two above   └─────────────────┘   contextual
                             │
                             ▼
                    ┌─────────────────┐
                    │ SELECTION RULE  │  + admissibility gates
                    └─────────────────┘  + cyber-only counterfactual
```

Each term is a **convex combination** of normalised factors — weights sum to
1.0 and factors lie in [0,1] — so scores land in [0,1] by construction and
are comparable across devices. The profile loader rejects any parameter set
that violates this, rather than silently producing out-of-range scores.

### 1.1 Cyber risk

```
CyberRisk = Σ wᵢ · fᵢ      where f ∈ {severity, confidence, anomaly,
                                      propagation, persistence, maturity}
```

**Deliberately asset-agnostic.** Device importance belongs to clinical risk.
Mixing it in would correlate the two terms, and the "without clinical
criticality" ablation would then measure a confounded quantity rather than a
clean removal. A test asserts that cyber risk is identical for the same
attack on a ventilator and a workstation.

Uncertainty is reported *alongside* the score rather than folded into it, so
the policy engine can require human approval when evidence is thin even
where the point estimate looks low. Sources: low detector confidence,
unidentified attack type, sparse corroborating evidence.

### 1.2 Clinical risk

```
ClinicalRisk = max( Σ wᵢ · gᵢ , applicable floors )
               where g ∈ {device criticality, patient dependency × acuity,
                          life support, operational state,
                          redundancy deficit, interruption intolerance}
```

This is the term **no public IoMT security dataset contains**, which is why
the closed-loop evaluation requires a simulator with clinical ground truth
(see [`datasets.md`](datasets.md)).

**Hard floors, not just weights.** A purely additive model can, under an
unlucky parameter sweep, return a low clinical risk for a ventilator
sustaining a life-critical patient — and low clinical risk is exactly what
permits a drastic response. The floors make that unreachable:

| Condition | Floor |
|---|---|
| Life-support relevant device + patient on life support + therapy in progress | 0.80 |
| Patient dependency = LIFE_CRITICAL | 0.75 |

A test drives every weight to the least-critical term and asserts the floor
still holds. This is what lets the sensitivity analysis explore the
parameter space without ever producing an unsafe recommendation.

The floors are declared in the profile, not hard-coded, because they are
part of the published formulation rather than hidden engineering.

### 1.3 Response impact

```
SecurityBenefit(action, attack) = ceiling(action) × effectiveness(attack, action)

ClinicalCost(action, device) = base(action)
                             × ClinicalRisk
                             × (1 − redundancy_discount if safe failover)
                             × (1 + 0.6 · interruption_overrun)
                             , then applicable floors
```

Two mechanisms matter here, and both were added after measurement rather
than by design intuition.

**Mechanism effectiveness.** With a fixed security-benefit table, the engine
selected `rotate_credentials` for *every* attack type — a ransomware-infected
workstation and a command-injected ventilator got the same response —
because that action had the best fixed benefit-to-cost ratio in all cases.
That is wrong on the facts: rotating credentials does nothing to a volumetric
flood, and blocking traffic does nothing to an attacker holding a valid
session. Security benefit is now the product of a containment ceiling and a
per-`(attack, action)` effectiveness multiplier. A test asserts that
structurally different attacks receive different responses.

**Contextual clinical cost.** The same action is near-free on a workstation
and potentially fatal on a ventilator, so a base cost is scaled by the
device's clinical risk, discounted where a validated failover peer exists,
and inflated where the interruption exceeds what the device and patient can
absorb.

**The UNSAFE gate is categorical, not threshold-based**, for one case:
interrupting life-sustaining therapy *with no safe alternative*. No
parameter sweep can reclassify that as merely HIGH.

> **A real ordering bug, recorded because it matters.** The life-support
> floor was initially applied *after* the redundancy discount, clobbering it
> — so a validated failover peer made no difference and redundancy was
> useless. Safe failover to a working peer is precisely the case where
> interrupting the compromised device is clinically acceptable. The floor now
> applies only when no safe alternative exists. Caught by a test asserting
> that redundancy lowers impact.

### 1.4 Selection

```
score(candidate) = w_sec · SecurityBenefit
                 − w_clin · ClinicalCost          (zero in the cyber-only ablation)
                 − w_inact · CyberRisk · (1 − SecurityBenefit)

select argmax over ADMISSIBLE candidates
```

Admissibility gates, applied before ranking:

1. **UNSAFE impact class** → inadmissible.
2. **Already attempted for this incident without achieving recovery** →
   inadmissible, so re-planning cannot blindly repeat a failed action
   (mandated scenario 3).

**The inaction penalty exists to prevent a specific failure.** Without it,
patient-awareness collapses into always choosing `monitor_only`, since doing
nothing has zero clinical cost. The penalty scales with cyber risk and with
how little the candidate achieves, so ignoring a serious attack is itself
costly. A test asserts the engine is not needlessly timid on non-clinical
assets.

**When nothing is admissible, the engine escalates to clinical staff rather
than acting.** The alternative — picking the least-bad inadmissible action —
would mean the engine can take an action it has itself judged unsafe. This
behaviour is observable: firmware tamper on a life-critical ventilator with
no redundancy rejects every effective containment option and escalates.

### 1.5 The counterfactual

Every decision records what a **cyber-risk-only** defender would have chosen:
`argmax SecurityBenefit`, ignoring clinical cost and the UNSAFE gate
entirely. This is what makes the contribution measurable rather than
asserted — the evaluation reports the divergence rate and the clinical harm
avoided on divergent cases.

The cyber-only ablation runs through the *same code path* with
`patient_aware=False`, so the comparison differs only in whether clinical
terms enter the objective, not in which implementation is used.

---

## 2. Observed behaviour

Measured with the default profile; reproduce with
`pytest tests/unit/test_risk_engine.py -v`.

| Case | Cyber | Clinical | Patient-aware | Cyber-only | Diverged |
|---|---|---|---|---|---|
| Workstation, ransomware | 0.76 | 0.14 | `isolate_network_segment` | `shutdown_device` | yes |
| DDoS on gateway | 0.52 | 0.28 | `isolate_network_segment` | `isolate_network_segment` | no |
| Port scan on gateway | 0.46 | 0.28 | `block_source_traffic` | `isolate_network_segment` | yes |
| ICU pump, ransomware | 0.76 | 0.73 | `quarantine_device` | `shutdown_device` | yes |
| Ventilator + safe failover, firmware tamper | 0.76 | 0.82 | `shutdown_device` | `shutdown_device` | no |
| **Ventilator, no redundancy, firmware tamper** | 0.76 | 1.00 | **`escalate_to_clinical_staff`** | `shutdown_device` | **yes** |
| Ventilator, no redundancy, command injection | 0.67 | 1.00 | `rotate_credentials` | `rotate_credentials` | no |

Three things to read from this table:

1. **The system is not timid.** DDoS on the gateway produces no divergence —
   decisive containment where there is no clinical cost. Patient-awareness
   that always chose the gentlest option would be useless.
2. **Redundancy changes the answer.** The same firmware tamper on the same
   device class yields `shutdown_device` where a validated failover peer
   exists, and escalation where none does.
3. **Divergence is not always harm-avoidance.** On command injection the two
   objectives agree, because credential rotation is both the most effective
   and the cheapest action. Divergence is a property of the *case*, not a
   constant benefit, and the evaluation must report the rate rather than
   assume it.

---

## 3. Threats to validity

Recorded so they appear in the paper rather than in review.

1. **Criticality assignment is an input, not a finding.** Device criticality
   tiers are configured. The sensitivity analysis shows how conclusions vary
   across plausible assignments; the work does not claim one correct
   assignment.
2. **Mechanism-effectiveness values are engineering judgements.** They
   encode defensible claims (credential rotation does not stop a flood;
   firmware tamper survives a restart) but are not empirically calibrated.
   The *ordering* is the defensible part; magnitudes are swept.
3. **Clinical cost is not clinical outcome.** The model expresses relative
   cost in a simulation. It is not validated against patient outcomes and
   must not be read as a clinical risk score.
4. **The additive form is a choice.** Multiplicative and lexicographic
   alternatives are plausible. The additive form was chosen for auditability
   — a clinician can be shown exactly which factor drove a decision — and
   every term is separately ablatable. Comparing formulation families is
   future work and is stated as such.
5. **No claim of optimality.** The selection rule is defensible and safe
   under the stated gates. It is not argued to be optimal in any
   decision-theoretic sense.

---

## 4. Reproducing and sweeping

```bash
# Inspect the active profile and its fingerprint
python -c "from risk_engine import RiskProfile; p=RiskProfile.load(); print(p.fingerprint())"

# Sweep a parameter
python -m experiments.runners.sensitivity --param decision.clinical_cost_weight \
       --values 0.1,0.3,0.55,0.8,0.95

# Run the cyber-only ablation
python -m experiments.runners.ablation --without clinical_context
```

Every risk result carries `formulation_version`, and every experiment
manifest records the profile **fingerprint** — a hash over the whole
parameter set — so any published number is traceable to the exact parameters
that produced it.
