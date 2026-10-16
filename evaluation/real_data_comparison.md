# Patient-safety comparison on the real CICIoMT2024 detector

Generated 2026-10-16T15:09:28.333050+00:00. Every one of the 1,614,182 rows of the official CICIoMT2024 WiFi+MQTT **test** split is one trial, scored by the XGBoost detector trained on the real train split (`evaluation/ciciomt2024_results.md`). The Risk Engine and Policy Engine are the real ones; the clinical device context is simulated (the dataset has none), sampled uniformly over 3 criticality levels x patient-dependent yes/no, and the whole comparison is repeated over 5 context seeds (cells show mean, then min to max across seeds).

## Detector at the runtime operating point

Detections fire when the predicted class is not benign and confidence >= 0.6. On this split: 1,573,325 fired; 1,576,575 rows are real attacks, 37,607 are benign; attack detection rate 99.72%; benign false-positive rate 3.12% (1,174 benign rows flagged).

High-stakes trials per seed (real attack AND HIGH-criticality, patient-dependent device): 263,116, 262,923, 262,730, 262,855, 261,250.

## Five systems

| System | Unsafe autonomous action rate | Unnecessary isolation rate |
|---|---|---|
| detection_only | 0.00% | 0.00% |
| fixed_response | 99.72% (99.70% to 99.75%) | 100.00% |
| detection_plus_agentic_ai | 0.00% | 50.48% (48.98% to 52.81%) |
| detection_plus_risk_engine | 99.72% (99.70% to 99.75%) | 100.00% |
| full_system | 0.00% | 50.48% (48.98% to 52.81%) |

- *Unsafe autonomous action rate*: among real attacks hitting a HIGH-criticality, patient-dependent device, the share where the system executed a disruptive action without a human.
- *Unnecessary isolation rate*: among detector false positives (benign traffic flagged), the share where the system autonomously isolated the device anyway. This is measurable here for the first time; the synthetic stand-in produced no false positives.
- `detection_only` is 0 on both by construction (it never acts), not a safety result.
- The unnecessary-isolation denominator is the same 1,174 benign rows the detector flagged in every seed, so that rate rests on a much smaller sample than the unsafe-action rate. It also means the full system, while never acting unsafely on a high-stakes device, still isolates a device autonomously on roughly half of the detector's false alarms (those landing on contexts the Policy Engine allows it to handle alone).

## Six ablations of `full_system`

| Ablation | Unsafe autonomous action rate | Unnecessary isolation rate | Trials differing from full_system (per seed) |
|---|---|---|---|
| without_healthcare_context | 0.00% | 50.48% (48.98% to 52.81%) | 0 to 0 |
| without_clinical_criticality | 0.00% | 50.48% (48.98% to 52.81%) | 0 to 0 |
| without_response_impact_assessment | 0.62% (0.60% to 0.63%) | 80.83% (79.98% to 81.86%) | 5,211 to 5,334 |
| without_agentic_ai | 99.72% (99.70% to 99.75%) | 100.00% | 785,951 to 787,713 |
| without_blockchain | 0.00% | 50.48% (48.98% to 52.81%) | 0 to 0 |
| without_recovery_verification | 0.00% | 50.48% (48.98% to 52.81%) | 0 to 0 |

`without_blockchain` and `without_recovery_verification` reuse `full_system`'s decision (neither component is on this harness's decision path), so their rows equal `full_system`'s by construction. First-seed `would_reopen_if_verified`: 0 of 785,612 autonomous executions.

## What this does and does not show

- The detector, Risk Engine and Policy Engine are real; the clinical context and the three LLM-backed agents are disclosed stand-ins. The result is about whether the decision layer gates autonomous action on clinical context, not about clinical outcomes.
- Device contexts are sampled, not observed; real hospital device mixes would change the denominators, not the gating logic.
- Variation across seeds reflects context sampling only; the detector is a single trained model (one training seed).
- Rates use the harness's own definitions (see `app/evaluation/baseline_systems.py`).
