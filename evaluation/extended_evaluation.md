# Extended evaluation (detector robustness, diagnostics, device-mix sensitivity, exhaustive policy check)

Added for the journal paper. Everything here is measured; nothing is typed from memory. Scripts are in `backend/app/evaluation/` and the raw outputs are the JSON files named below. Data: the official CICIoMT2024 WiFi+MQTT test split (1,614,182 flows), scored whole.

## 1. Six classifiers x five training seeds (`detector_multiseed.json`, `run_detector_multiseed.py`)

At most 30,000 training flows per class (the main model uses up to 300,000), so the XGBoost row is a different model from `ciciomt2024_results.md`. A seed changes the training sample and the model's randomness. Mean +/- sample standard deviation over seeds 0-4.

| Classifier | Accuracy (19) | Macro-F1 (19) | Attack detection | Benign FPR | Train (s) |
|---|---|---|---|---|---|
| Decision tree | 0.9950 +/- 0.0003 | 0.9080 +/- 0.0051 | 0.9996 | 0.0857 +/- 0.0037 | 8 |
| Logistic regression (SGD, log-scaled features, untuned) | 0.6200 +/- 0.0296 | 0.5690 +/- 0.0084 | 0.9993 | 0.1902 +/- 0.0054 | 69 |
| Random forest | 0.9922 +/- 0.0010 | 0.8783 +/- 0.0131 | 0.9993 | 0.0499 +/- 0.0107 | 50 |
| Extra trees | 0.9896 +/- 0.0001 | 0.8600 +/- 0.0011 | 0.9994 | 0.0604 +/- 0.0026 | 23 |
| Neural network (1 hidden layer of 64, untuned) | 0.6883 +/- 0.0389 | 0.6616 +/- 0.0099 | 0.9994 | 0.1303 +/- 0.0386 | 55 |
| XGBoost | 0.9953 +/- 0.0002 | 0.9103 +/- 0.0017 | 0.9997 | 0.0671 +/- 0.0078 | 88 |

Reading: tree models cluster; XGBoost's edge over a single decision tree (0.0003 accuracy, 0.0023 macro-F1) is about half the tree's seed-to-seed spread, so it is a stability argument, not a large accuracy gain. The linear and neural baselines were not tuned and are weak; do not read them as the best those model families can do.

## 2. Diagnostics of the shipped XGBoost model (`detector_diagnostics.json`, `run_detector_diagnostics.py`)

- 95% bootstrap intervals (1,000 multinomial resamples of the confusion cells): accuracy 0.9951-0.9953; macro-F1 0.9233-0.9291; attack detection 0.99970-0.99975; benign FPR 0.0489-0.0533. Rows are treated as independent, which they are not (flows inside a capture are correlated), so these understate across-capture uncertainty.
- Largest confusions: benign -> ARP spoofing 1,631; DDoS-ICMP -> DoS-ICMP 1,309; MQTT DDoS-Publish -> DoS-Publish 1,056; port scan <-> OS scan 582 / 463. Family level: DoS -> DDoS 470, DDoS -> DoS 1,646.
- Binary attack-vs-benign by 1 - P(Benign): ROC AUC 0.99996, average precision 0.999999. At 99.5% attack detection the benign FPR is 0.0 on this split; at 99.9% it is 0.11%; at 99.95% it is 2.3%. (Observation only; not used to choose a threshold.)
- Calibration of the shipped model: ECE 0.0035 raw, 0.0033 after T = 0.917 (T fitted on the dev model's validation data, applied unchanged). 1,559,351 of 1,614,182 flows are in the top confidence bin (mean confidence 0.9999, accuracy 0.9994); the bin of 3,387 flows with confidence 0.73-0.80 has accuracy 0.54.

## 3. Sensitivity to the clinical device mix (`context_sensitivity.json`, `run_context_sensitivity.py`)

Each setting: 121,174 sampled trials (all 1,174 detector false alarms + 120,000 random other test flows), one context seed. Rates are conditional, so oversampling false alarms does not bias them.

| Patient-dependent share | High-stakes trials | Unsafe, fixed response | Unsafe, full system | Unsafe, no response-impact | False alarms isolated, full system | Autonomy retained |
|---|---|---|---|---|---|---|
| 0% | 0 | n/a | n/a | n/a | 1,174 / 1,174 | 100.0% |
| 10% | 3,799 | 3,786 | 0 | 22 | 1,075 / 1,174 | 90.0% |
| 25% | 9,616 | 9,585 | 0 | 66 | 905 / 1,174 | 75.0% |
| 50% | 19,295 | 19,246 | 0 | 132 | 611 / 1,174 | 50.1% |
| 75% | 29,164 | 29,088 | 0 | 184 | 283 / 1,174 | 25.0% |
| 90% | 35,181 | 35,090 | 0 | 222 | 130 / 1,174 | 9.9% |
| 100% | 39,142 | 39,043 | 0 | 246 | 0 / 1,174 | 0.0% |

HIGH-criticality share 0 / 33 / 60 / 100% (half the devices patient-dependent): full-system unsafe 0 in all (high-stakes trials 0 / 19,595 / 35,192 / 58,621); false alarms isolated 601 / 586 / 595 / 582 of 1,174; autonomy 50.0-50.1%. Routing depends on patient dependency, not on criticality alone.

## 4. Exhaustive check of the real Risk + Policy engines (`policy_exhaustive.json`, `run_policy_exhaustive.py`)

3,168 inputs = 11 action categories x 3 criticalities x 2 dependency values x 4 clinical-impact levels x 4 threat severities x 3 threat confidences. 1,872 autonomous, 1,296 human.

| Context | Inputs | Autonomous | Human |
|---|---|---|---|
| low / medium / HIGH criticality, not patient-dependent | 528 each | 528 each | 0 |
| low / medium criticality, patient-dependent | 528 each | 144 each | 384 each |
| HIGH criticality, patient-dependent | 528 | 0 | 528 |

- Severe action autonomous on a patient-dependent device: 0 violations among 576 inputs.
- Any action autonomous on a HIGH-criticality, patient-dependent device: 0 violations among 528 inputs.
- Routing independent of stated severity and confidence: true.
- Design fact worth knowing: HIGH-criticality devices with no patient dependency are fully autonomous, including severe actions.

## Not done / limits

- Fault-injection study unchanged (30 scripted runs, 3 devices); no live-LLM numbers (provider 503/429).
- Fabric evaluation unchanged (one orderer, one 2-CPU host, one run).
- Clinical context is sampled, not observed; agents in the large studies are deterministic stand-ins.
- No unit tests were written for the four new scripts; they were run end to end and lint-checked.
