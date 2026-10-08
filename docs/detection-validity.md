# Detection validity: avoiding a trivially-separable task

## The problem found during development

Early feature-separability analysis on the simulator showed several features
that **perfectly separate** attack from benign windows — zero variance in
benign traffic, non-zero under attack:

| Scenario | Feature | Benign mean | Attack mean |
|---|---|---|---|
| `mitm_monitor` | `tls_downgrade` | 0.000 | 0.897 |
| `mitm_monitor` | `rtt_ms` | 0.000 | 41.015 |
| `mitm_monitor` | `duplicate_mac_observed` | 0.000 | 1.000 |
| `network_flood_icu` | `is_udp` | 0.000 | 1.000 |
| `s2_ventilator_compromise` | `source_offsegment` | 0.000 | 0.026 |

A classifier trained on these learns a single threshold and reports
F1 ≈ 1.00. **Those metrics would be worthless**, and a reviewer examining
feature importance would immediately identify the task as degenerate.

This is a known failure mode in synthetic-data security research: the
generator plants a signal that only the attack path produces, so the
"detector" is really reading a label in disguise. It inflates published
results across the subfield and is a standard reviewer objection.

## Root cause (found after four failed feature-level patches)

Patching individual features did not work. `packets`, `syn_ratio`, `is_arp`
and `distinct_dst_hosts` each reached AUC ≈ 1.0 in turn, because each was a
proxy for the same underlying artifact:

> **Every attack sent traffic from a source address that benign traffic
> never used.** Benign flows involved a fixed set of two or three peers, so
> "an unseen peer appeared" was a perfect label, and *any* feature touching
> flow identity or record structure encoded it.

The measurement that identified this: on `stealth_low_rate_dos`, a
1.5 %-intensity attack whose own packet rate (414 pps mean) was **lower**
than the benign baseline (622 pps mean) still reached AUC 0.985 on summed
`packets` — purely because it reliably added +1.09 flow records per tick.
The classifier was counting records, not reading traffic.

**Fix:** benign traffic now has a churning peer population — roaming
clinician devices, imaging modalities, vendor update endpoints, other wards'
gateways, EHR replicas. A new peer is unremarkable, so detection must rely
on behaviour. This single change resolved all four features at once.

Secondary fix: volume features aggregate as window **maximum** and **median**
rather than sums, so they do not grow mechanically with the flow-record
count, and `distinct_dst_hosts` is a ratio rather than a count.

## Why this happens structurally

A naive simulator emits attack indicators **only** on the attack path:

```
benign path  ->  rtt_ms absent  ->  feature = 0.0
attack path  ->  rtt_ms = 41.0  ->  feature = 41.0
```

The feature's *presence* is the label. No amount of model sophistication
fixes this; the data is broken.

## The three mitigations applied

### 1. Benign baseline occupancy

Every feature that an attack can elevate must have a **non-degenerate benign
distribution**. Benign traffic now legitimately produces:

- non-zero `rtt_ms` (normal network round-trip latency, with jitter)
- non-zero `ttl_variance` (routing variation)
- occasional benign `duplicate_mac_observed` (DHCP lease churn, VM migration,
  NIC failover — all real causes of transient MAC conflicts)
- occasional benign `tls_downgrade` (legacy devices that genuinely negotiate
  plaintext — a real and common hospital condition)
- protocol mix including benign UDP (DNS, NTP, SNMP, mDNS)
- occasional benign off-segment commands (biomedical engineering access from
  a maintenance VLAN)
- occasional benign authentication failures (mistyped passwords)

These are not noise injected to make the problem artificially hard. Each is a
real phenomenon in hospital networks, and **its absence was the bug.**

### 2. Attack/benign distribution overlap

Attack intensity is sampled rather than fixed, so low-intensity attacks fall
inside the benign range and must be distinguished by *combinations* of
features rather than any single one. This is what makes the task require a
model.

### 3. Degeneracy test in CI

`tests/unit/test_detection_validity.py` asserts that **no single feature
achieves AUC above a threshold** on any scenario. If a future change
reintroduces a planted signal, CI fails with the offending feature named.

## Measured outcome

Maximum single-feature AUC after the fixes:

| Scenario | Max single-feature AUC | Assessment |
|---|---|---|
| `mixed_difficulty_corpus` (primary) | **0.780** | Requires a model |
| `stealth_passive_mitm` | 0.887 | Hard |
| `s2_ventilator_compromise` | 0.918 | Non-degenerate |
| `stealth_slow_recon` | 0.959 | Hard |
| `stealth_low_rate_dos` | 0.963 | Hard |
| `stealth_credential_creep` | 0.977 | Hard |
| `network_flood_icu` | 0.999 | **Correctly easy** |

`network_flood_icu` remaining near 1.0 is the right answer, not a defect: a
full-intensity volumetric DDoS genuinely *is* trivially detectable. The
corpus must contain such cases alongside the hard tail. What matters is that
the **primary training/evaluation corpus** is not dominated by them.

## What we report

- **Per-feature univariate AUC** is published alongside every detection
  result, so a reader can confirm no single feature dominates.
- Detection metrics on **CICIoMT2024** (real captured traffic) are the
  headline detection numbers; simulator detection metrics are reported as
  secondary and explicitly labelled simulator-derived.
- The simulator's purpose is the **closed-loop decision evaluation**, where
  no public dataset can substitute — not to claim detection performance.

## Residual limitation (stated in the paper)

Even with these mitigations, a simulator cannot fully reproduce the
irreducible messiness of production hospital traffic. We therefore do not
claim that simulator detection performance transfers to deployment. That is
precisely why detection is benchmarked on real captured data
(CICIoMT2024) and the simulator is used for what it is uniquely able to
test: the response decision under known clinical ground truth.
