# Calibrated confidence gate: tau chosen on validation, scored once on test

Generated 2026-10-16T16:35:19.008709+00:00. Experiment-only (the shipped Policy Engine gate is off by default and takes its threshold from `POLICY_MIN_AUTONOMOUS_CONFIDENCE`). Protocol and selection rule are in `backend/app/evaluation/run_calibrated_gating.py`'s docstring and were fixed before any result was seen.

## Headline

The selection rule (largest tau keeping at least 95% of real-attack autonomy **on validation**) chose **tau = 0.7** on the calibrated confidence. On the untouched test split that tau left 41.5% (40.0% to 43.2%) of the detector's 1,558 false alarms with autonomous action (ungated: 50.5% (48.8% to 52.1%)), while the system still acted on its own for 99.9% (99.9% to 99.9%) of the real attacks it would otherwise have handled, and unsafe autonomous actions stayed at 0.0%.

## Splits

* Dev-model training rows (after the per-class cap of 300,000): 2,818,999.
* Validation rows: 1,366,808 (benign 38,547, attack 1,328,261).
* Test rows: 1,614,182 (benign 37,607, attack 1,576,575).
* How each class was held out (see `validation.split_method` in the JSON): classes with several captures hold out their last capture whole; Benign and ARP_Spoofing (one capture each) hold out a contiguous tail block with a gap.

## Detector and calibration

Dev model on the test split: 19-class accuracy 99.51%, benign false-positive rate at the runtime threshold 4.14% (validation: 1.25%).

Temperature fitted on validation: T = 0.917.

| | NLL | ECE (15 bins) |
|---|---|---|
| validation, raw | 0.1504 | 0.0409 |
| validation, calibrated | 0.1495 | 0.0288 |
| test, raw | 0.0204 | 0.0033 |
| test, calibrated | 0.0210 | 0.0030 |

## Validation sweep (this is where tau was chosen)

| tau (calibrated) | Unnecessary isolation (of false alarms) | Unsafe autonomous action | Real-attack autonomy retained | Extra approvals per 1,000 detections |
|---|---|---|---|---|
| no gate | 48.7% (45.2% to 51.9%) | 0.0% | 100.0% | 0.00 |
| 0.6 | 48.7% (45.2% to 51.9%) | 0.0% | 100.0% | 0.00 |
| 0.7 **(selected on validation)** | 35.9% (32.8% to 38.8%) | 0.0% | 97.1% (97.1% to 97.1%) | 14.56 |
| 0.8 | 24.5% (21.4% to 26.8%) | 0.0% | 93.9% (93.8% to 93.9%) | 30.81 |
| 0.9 | 15.5% (13.9% to 16.2%) | 0.0% | 84.8% (84.7% to 84.8%) | 76.27 |
| 0.95 | 12.0% (10.6% to 13.1%) | 0.0% | 80.1% (80.1% to 80.1%) | 99.60 |
| 0.99 | 8.8% (7.9% to 9.5%) | 0.0% | 79.5% (79.4% to 79.5%) | 102.72 |
| 0.999 | 6.0% (5.8% to 6.6%) | 0.0% | 79.0% (79.0% to 79.0%) | 105.15 |

Denominator of the unnecessary-isolation column: 482 validation false alarms.

## Test sweep (shown for transparency; played no part in the choice)

| tau (calibrated) | Unnecessary isolation (of false alarms) | Unsafe autonomous action | Real-attack autonomy retained | Extra approvals per 1,000 detections |
|---|---|---|---|---|
| no gate | 50.5% (48.8% to 52.1%) | 0.0% | 100.0% | 0.00 |
| 0.6 | 50.5% (48.8% to 52.1%) | 0.0% | 100.0% | 0.00 |
| 0.7 **(selected on validation)** | 41.5% (40.0% to 43.2%) | 0.0% | 99.9% (99.9% to 99.9%) | 0.58 |
| 0.8 | 31.6% (30.2% to 32.9%) | 0.0% | 99.8% (99.8% to 99.8%) | 1.35 |
| 0.9 | 20.9% (19.6% to 22.0%) | 0.0% | 99.6% (99.6% to 99.6%) | 2.36 |
| 0.95 | 14.0% (13.0% to 15.2%) | 0.0% | 97.2% (97.2% to 97.2%) | 14.21 |
| 0.99 | 2.8% (2.6% to 3.3%) | 0.0% | 96.8% (96.8% to 96.8%) | 16.45 |
| 0.999 | 1.1% (0.8% to 1.3%) | 0.0% | 96.4% (96.4% to 96.4%) | 18.59 |

Denominator: 1,558 test false alarms.

## Reading this honestly

- **Validation is optimistic for the classes that matter most here.** Benign and ARP_Spoofing have one training capture each, so their validation rows are a later stretch of the same capture. Validation benign false-positive rate 1.25% vs test 4.14% shows the size of that gap; a tau chosen on validation can transfer worse than the validation table suggests, and the test table is where to look for that.
- **Transfer check.** At tau 0.95, real-attack autonomy retained is 80.1% on validation vs 97.2% on test: validation was HARSHER than test for real attacks (the held-out validation captures are less confidently detected than the test captures), so a retention floor applied on validation picks a more conservative tau than the test split would have allowed. The false-alarm side moves the other way for the reason in the first bullet. Either way the headline number above is a single-split, single-model result.
- One detector training seed, one calibration fit, 5 device-context seeds; the contexts are sampled, not observed.
- The false-alarm sample is small and concentrated in one predicted class (ARP_Spoofing), so the gate's benefit may largely be that class's weakness showing up in its confidence.
- Temperature scaling fixes the confidence's scale, not the detector: the same rows are misclassified before and after. It does not make the detector robust to a different network.
- The 95% retention floor is a policy choice (how much autonomy a hospital will trade for fewer false-alarm isolations), not a derived constant; the whole validation sweep is above so another floor can be read off.
- In the live system the confidence given to the gate is the Threat Reasoning Agent's, which relays the detector's; a calibrated detector confidence would have to be threaded through from the detection event for the numbers here to apply as measured.
