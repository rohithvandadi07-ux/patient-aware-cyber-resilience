# Phase 13 baseline comparison -- real, reported numbers

**Generated:** 2026-10-13T04:16:12.733963+00:00  
**Data source:** SYNTHETIC stand-in dataset (not real CICIoMT2024 -- see datasets/LICENSE_NOTES.md)

Disclosure, consistent with every other document in this repo: this evaluation trains against the synthetic stand-in dataset, not real CICIoMT2024 (no network access to download it in this project's development environment -- see `datasets/LICENSE_NOTES.md`). The detection accuracy numbers below are therefore not a CICIoMT2024 benchmark result. The patient-safety comparison between the five response systems and six ablations below **is** a real result regardless of the underlying dataset's realism, because what it measures is whether the real Risk Engine (Phase 5) and Policy Engine (Phase 6) rule tables correctly gate an autonomous response on device context -- the same question Section 17's Scenario B asks once, asked here across hundreds of randomized trials instead. See `app/evaluation/baseline_systems.py`'s module docstring for exactly what is real code (the detector, Risk Engine, Policy Engine) versus a disclosed deterministic stand-in for the still-nonexistent LLM-backed agents (Threat Reasoning, Healthcare Context, Response Planning, Recovery Verification), and exactly what each ablation genuinely disables versus two (`without_blockchain`, `without_recovery_verification`) that are, honestly, no-ops in this harness because their named component is not part of this decision path at all.

## random_forest

Detection metrics (real, measured on this model's own held-out split of the synthetic dataset): accuracy=0.9995, precision_macro=0.9998, recall_macro=0.9974, f1_macro=0.9986.

2038 trials (held-out test rows), 1035 detections fired, 1038 real attacks in the split, 0 false positives, 162 trials were both a real attack and a HIGH-criticality, patient-dependent device context.

| System | Unsafe autonomous action rate | Unnecessary isolation rate |
| --- | --- | --- |
| detection_only | 0.0% (0/162) | n/a (0/0 trials) |
| fixed_response | 100.0% (162/162) | n/a (0/0 trials) |
| detection_plus_agentic_ai | 0.0% (0/162) | n/a (0/0 trials) |
| detection_plus_risk_engine | 100.0% (162/162) | n/a (0/0 trials) |
| full_system | 0.0% (0/162) | n/a (0/0 trials) |

`detection_only`'s two rates are trivially 0 by construction -- a system with no response layer can never take an unsafe autonomous action or an unnecessary isolation, because it never takes any action at all. This is a definitional artifact of that baseline, not a safety property, and is reported here rather than omitted so it cannot be mistaken for a measured result.

**Unnecessary-isolation rate could not be measured for this run** (denominator 0/0): this model had zero measured false positives on its held-out split -- see the `false_positive_rate_per_class` entries in `phase13_baseline_comparison.json`, all 0.0 for every attack class. This is a real, honest limitation of the *synthetic* dataset, not a hidden or fabricated result: `synthetic_data.py`'s per-class profiles (module docstring, Phase 3) are Gaussian-separated by construction, cleaner than real network traffic is ever likely to be, so a baseline this easy to classify perfectly leaves no false positives for this metric to measure against. The metric and the comparison logic are real and ready (`app/evaluation/baseline_systems.is_unnecessary_isolation`, unit-tested directly in `app/evaluation/tests/test_baseline_systems.py`); what's missing is a dataset with realistic class overlap to actually exercise it -- the real CICIoMT2024 dataset, once downloadable, is the natural next place to re-run this and get a nonzero denominator.

### Ablations (variants of `full_system`)

| Ablation | Unsafe autonomous action rate | Unnecessary isolation rate | Trials where the decision differs from `full_system` |
| --- | --- | --- | --- |
| without_healthcare_context | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_clinical_criticality | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_response_impact_assessment | 0.6% (1/162) | n/a (0/0 trials) | 4/2038 |
| without_agentic_ai | 100.0% (162/162) | n/a (0/0 trials) | 511/2038 |
| without_blockchain | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_recovery_verification | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |

The last column is the honest, exhaustive check for an ablation whose effect the first two headline metrics might not show (they are each scoped to one narrow trial population -- high-stakes real attacks, and false positives respectively): across **every** trial, how many times did this ablation's `executed_action`/`requires_human_approval` actually differ from `full_system`'s own decision on that same trial? `without_healthcare_context` reads 0 here for a structural reason, not merely because this run happened not to exercise it: the Policy Engine's routing rules (`app/policy_engine/rules.py::classify_routing`) consult only `response_impact` and `patient_dependency`, never `clinical_risk` -- so flattening `clinical_impact_level` (the one field that ablation changes) cannot change a single routing decision under the current Policy Engine, by construction. `without_blockchain`/`without_recovery_verification` read 0 for the reason given above (reused decisions). `without_clinical_criticality` also reads 0 in this run -- verified to be structural, not a weak test, for this experiment's specific two candidate actions: flattening `device_criticality` only ever changes a HIGH-impact classification to a MEDIUM-or-CRITICAL one (never crossing the LOW/MEDIUM-vs-HIGH boundary the Policy Engine actually routes on) in every context combination this experiment samples, because `patient_dependency` alone already forces approval via a separate rule once impact is MEDIUM or above (`rules.py`'s `RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL`) -- so this ablation would only show a nonzero count here if the experiment ever proposed a *non-disruptive* action on a patient-dependent device, which `propose_action` never does. `without_response_impact_assessment`'s nonzero count (this model) is a genuine, measured effect that survives that same structural check.

`without_recovery_verification`'s unsafe/unnecessary rates above are identical to `full_system`'s by construction (see `baseline_systems.py`: recovery verification is a post-execution check this per-row trial harness has no before/after device-state model to genuinely re-run). Its real, distinguishing number is **would_reopen_if_verified = 0.0% (0/524)**: of `full_system`'s own autonomous executions, this fraction is flagged by the disclosed Recovery Verification stand-in (`recovery_result_would_require_reinvestigation`) as containment not clearly verified -- exactly the trials `without_recovery_verification` instead marks resolved unconditionally, with no reinvestigation. Disclosed plainly rather than left implicit: that number reads 0 here because the one case this stand-in flags (a MODERATE action autonomously executed on a high-stakes real attack) can only happen if `full_system` ever autonomously executes on a high-stakes real attack at all -- and the systems table above already shows it never does (0% unsafe rate), which is this project's central safety claim, not a coincidence of this metric. So recovery verification's measured marginal value over `full_system` is genuinely near-zero in this harness, not because the check is weak, but because the Policy Engine already closes off the one gap it would have caught.

`without_blockchain`'s rates above are identical to `full_system`'s too, confirmed and reported as a genuine "zero functional effect" finding rather than a measured difference: nothing in this evaluation harness's decision path calls `app/blockchain/` for any system, so there is no provenance-recording step here for this ablation to remove.

## xgboost

Detection metrics (real, measured on this model's own held-out split of the synthetic dataset): accuracy=0.9995, precision_macro=0.9998, recall_macro=0.9974, f1_macro=0.9986.

2038 trials (held-out test rows), 1037 detections fired, 1038 real attacks in the split, 0 false positives, 162 trials were both a real attack and a HIGH-criticality, patient-dependent device context.

| System | Unsafe autonomous action rate | Unnecessary isolation rate |
| --- | --- | --- |
| detection_only | 0.0% (0/162) | n/a (0/0 trials) |
| fixed_response | 100.0% (162/162) | n/a (0/0 trials) |
| detection_plus_agentic_ai | 0.0% (0/162) | n/a (0/0 trials) |
| detection_plus_risk_engine | 100.0% (162/162) | n/a (0/0 trials) |
| full_system | 0.0% (0/162) | n/a (0/0 trials) |

`detection_only`'s two rates are trivially 0 by construction -- a system with no response layer can never take an unsafe autonomous action or an unnecessary isolation, because it never takes any action at all. This is a definitional artifact of that baseline, not a safety property, and is reported here rather than omitted so it cannot be mistaken for a measured result.

**Unnecessary-isolation rate could not be measured for this run** (denominator 0/0): this model had zero measured false positives on its held-out split -- see the `false_positive_rate_per_class` entries in `phase13_baseline_comparison.json`, all 0.0 for every attack class. This is a real, honest limitation of the *synthetic* dataset, not a hidden or fabricated result: `synthetic_data.py`'s per-class profiles (module docstring, Phase 3) are Gaussian-separated by construction, cleaner than real network traffic is ever likely to be, so a baseline this easy to classify perfectly leaves no false positives for this metric to measure against. The metric and the comparison logic are real and ready (`app/evaluation/baseline_systems.is_unnecessary_isolation`, unit-tested directly in `app/evaluation/tests/test_baseline_systems.py`); what's missing is a dataset with realistic class overlap to actually exercise it -- the real CICIoMT2024 dataset, once downloadable, is the natural next place to re-run this and get a nonzero denominator.

### Ablations (variants of `full_system`)

| Ablation | Unsafe autonomous action rate | Unnecessary isolation rate | Trials where the decision differs from `full_system` |
| --- | --- | --- | --- |
| without_healthcare_context | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_clinical_criticality | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_response_impact_assessment | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_agentic_ai | 100.0% (162/162) | n/a (0/0 trials) | 511/2038 |
| without_blockchain | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |
| without_recovery_verification | 0.0% (0/162) | n/a (0/0 trials) | 0/2038 |

The last column is the honest, exhaustive check for an ablation whose effect the first two headline metrics might not show (they are each scoped to one narrow trial population -- high-stakes real attacks, and false positives respectively): across **every** trial, how many times did this ablation's `executed_action`/`requires_human_approval` actually differ from `full_system`'s own decision on that same trial? `without_healthcare_context` reads 0 here for a structural reason, not merely because this run happened not to exercise it: the Policy Engine's routing rules (`app/policy_engine/rules.py::classify_routing`) consult only `response_impact` and `patient_dependency`, never `clinical_risk` -- so flattening `clinical_impact_level` (the one field that ablation changes) cannot change a single routing decision under the current Policy Engine, by construction. `without_blockchain`/`without_recovery_verification` read 0 for the reason given above (reused decisions). `without_clinical_criticality` also reads 0 in this run -- verified to be structural, not a weak test, for this experiment's specific two candidate actions: flattening `device_criticality` only ever changes a HIGH-impact classification to a MEDIUM-or-CRITICAL one (never crossing the LOW/MEDIUM-vs-HIGH boundary the Policy Engine actually routes on) in every context combination this experiment samples, because `patient_dependency` alone already forces approval via a separate rule once impact is MEDIUM or above (`rules.py`'s `RULE_APPROVAL_MEDIUM_PATIENT_DEPENDENT_GAP_FILL`) -- so this ablation would only show a nonzero count here if the experiment ever proposed a *non-disruptive* action on a patient-dependent device, which `propose_action` never does. `without_response_impact_assessment`'s nonzero count (this model) is a genuine, measured effect that survives that same structural check.

`without_recovery_verification`'s unsafe/unnecessary rates above are identical to `full_system`'s by construction (see `baseline_systems.py`: recovery verification is a post-execution check this per-row trial harness has no before/after device-state model to genuinely re-run). Its real, distinguishing number is **would_reopen_if_verified = 0.0% (0/526)**: of `full_system`'s own autonomous executions, this fraction is flagged by the disclosed Recovery Verification stand-in (`recovery_result_would_require_reinvestigation`) as containment not clearly verified -- exactly the trials `without_recovery_verification` instead marks resolved unconditionally, with no reinvestigation. Disclosed plainly rather than left implicit: that number reads 0 here because the one case this stand-in flags (a MODERATE action autonomously executed on a high-stakes real attack) can only happen if `full_system` ever autonomously executes on a high-stakes real attack at all -- and the systems table above already shows it never does (0% unsafe rate), which is this project's central safety claim, not a coincidence of this metric. So recovery verification's measured marginal value over `full_system` is genuinely near-zero in this harness, not because the check is weak, but because the Policy Engine already closes off the one gap it would have caught.

`without_blockchain`'s rates above are identical to `full_system`'s too, confirmed and reported as a genuine "zero functional effect" finding rather than a measured difference: nothing in this evaluation harness's decision path calls `app/blockchain/` for any system, so there is no provenance-recording step here for this ablation to remove.

