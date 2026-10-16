# Confidence gate sweep on the real CICIoMT2024 detector

Generated 2026-10-16T15:56:31.813716+00:00. Experiment-only: the gate (`decide_full_system_confidence_gated`) is not part of the Policy Engine. Scored on all 1,614,182 official test rows, 5 device-context seeds (cells: mean, then min to max across seeds). The tau grid was fixed before running and is reported in full.

## Does confidence separate real attacks from false alarms?

Among detections that fire (confidence >= 0.6): 1,572,151 real attacks vs 1,174 false alarms. Median confidence: real attacks 1.0000, false alarms 0.7583. AUROC of confidence for telling them apart: 0.9893. 94.4% of the false alarms were predicted as ARP spoofing, the detector's weakest class (see `ciciomt2024_results.md`).

## Gate sweep

| tau | Unnecessary isolation (of false alarms) | Unsafe autonomous action | Real-attack autonomy retained | Extra approvals per 1,000 detections |
|---|---|---|---|---|
| 0.6 | 50.5% (49.0% to 52.8%) | 0.0% (0.0% to 0.0%) | 100.0% (100.0% to 100.0%) | 0.00 |
| 0.7 | 36.2% (35.3% to 38.1%) | 0.0% (0.0% to 0.0%) | 99.8% (99.8% to 99.8%) | 0.86 |
| 0.8 | 22.9% (21.6% to 23.9%) | 0.0% (0.0% to 0.0%) | 99.6% (99.6% to 99.6%) | 2.14 |
| 0.9 | 13.0% (12.3% to 13.9%) | 0.0% (0.0% to 0.0%) | 97.2% (97.2% to 97.2%) | 14.43 |
| 0.95 | 3.2% (2.5% to 3.7%) | 0.0% (0.0% to 0.0%) | 97.1% (97.1% to 97.1%) | 15.00 |
| 0.99 | 0.6% (0.4% to 0.8%) | 0.0% (0.0% to 0.0%) | 96.8% (96.8% to 96.8%) | 16.22 |
| 0.999 | 0.0% (0.0% to 0.0%) | 0.0% (0.0% to 0.0%) | 96.3% (96.3% to 96.4%) | 18.66 |

- tau = 0.6 equals the runtime detection threshold, so the gate does nothing and reproduces the earlier `full_system` numbers (a built-in consistency check).
- *Unnecessary isolation*: share of the detector's false alarms where the system still acted on its own. Denominator: 1,174 false alarms (same rows every seed), a small sample.
- *Real-attack autonomy retained*: of the real attacks the system would have handled autonomously without the gate, the share it still handles autonomously. The rest wait for a human, which is the cost of the gate.
- *Unsafe autonomous action* must stay 0.0%: the gate only ever removes autonomous actions.

## Reading this honestly

- The curves show confidence is informative here; they do **not** pick a deployable tau. Calibrating tau needs validation data held out from both training and this test split.
- Real-attack confidences are almost all ~1.0 because the volumetric floods are easy; whether that holds on another network or against evasive traffic is untested.
- XGBoost's softmax confidence is not calibrated; a calibrated probability would make the threshold interpretable.
- The false-alarm sample is small (one detector, one test capture set) and concentrated in one predicted class, so the gate's benefit may largely reflect that class's weakness.
- Vectorised path re-checked against the real gated function on 3,000 random trials x every tau: no mismatches.
