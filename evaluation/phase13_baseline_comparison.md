# Phase 13 baseline comparison -- real, reported numbers

**Generated:** 2026-10-12T09:03:06.347649+00:00  
**Data source:** SYNTHETIC stand-in dataset (not real CICIoMT2024 -- see datasets/LICENSE_NOTES.md)

Disclosure, consistent with every other document in this repo: this evaluation trains against the synthetic stand-in dataset, not real CICIoMT2024 (no network access to download it in this project's development environment -- see `datasets/LICENSE_NOTES.md`). The detection accuracy numbers below are therefore not a CICIoMT2024 benchmark result. The patient-safety comparison between the three response systems **is** a real result regardless of the underlying dataset's realism, because what it measures is whether the real Risk Engine (Phase 5) and Policy Engine (Phase 6) rule tables correctly gate an autonomous response on device context -- the same question Section 17's Scenario B asks once, asked here across hundreds of randomized trials instead. See `app/evaluation/baseline_systems.py`'s module docstring for exactly what is real code (the detector, Risk Engine, Policy Engine) versus a disclosed deterministic stand-in for the still-nonexistent LLM-backed agents (Threat Reasoning, Healthcare Context, Response Planning).

## random_forest

Detection metrics (real, measured on this model's own held-out split of the synthetic dataset): accuracy=0.9995, precision_macro=0.9998, recall_macro=0.9974, f1_macro=0.9986.

2038 trials (held-out test rows), 1035 detections fired, 1038 real attacks in the split, 0 false positives, 162 trials were both a real attack and a HIGH-criticality, patient-dependent device context.

| System | Unsafe autonomous action rate | Unnecessary isolation rate |
| --- | --- | --- |
| detection_only | 0.0% (0/162) | n/a (0/0 trials) |
| fixed_response | 100.0% (162/162) | n/a (0/0 trials) |
| full_system | 0.0% (0/162) | n/a (0/0 trials) |

`detection_only`'s two rates are trivially 0 by construction -- a system with no response layer can never take an unsafe autonomous action or an unnecessary isolation, because it never takes any action at all. This is a definitional artifact of that baseline, not a safety property, and is reported here rather than omitted so it cannot be mistaken for a measured result.

**Unnecessary-isolation rate could not be measured for this run** (denominator 0/0): this model had zero measured false positives on its held-out split -- see the `false_positive_rate_per_class` entries in `phase13_baseline_comparison.json`, all 0.0 for every attack class. This is a real, honest limitation of the *synthetic* dataset, not a hidden or fabricated result: `synthetic_data.py`'s per-class profiles (module docstring, Phase 3) are Gaussian-separated by construction, cleaner than real network traffic is ever likely to be, so a baseline this easy to classify perfectly leaves no false positives for this metric to measure against. The metric and the comparison logic are real and ready (`app/evaluation/baseline_systems.is_unnecessary_isolation`, unit-tested directly in `app/evaluation/tests/test_baseline_systems.py`); what's missing is a dataset with realistic class overlap to actually exercise it -- the real CICIoMT2024 dataset, once downloadable, is the natural next place to re-run this and get a nonzero denominator.

## xgboost

Detection metrics (real, measured on this model's own held-out split of the synthetic dataset): accuracy=0.9995, precision_macro=0.9998, recall_macro=0.9974, f1_macro=0.9986.

2038 trials (held-out test rows), 1037 detections fired, 1038 real attacks in the split, 0 false positives, 162 trials were both a real attack and a HIGH-criticality, patient-dependent device context.

| System | Unsafe autonomous action rate | Unnecessary isolation rate |
| --- | --- | --- |
| detection_only | 0.0% (0/162) | n/a (0/0 trials) |
| fixed_response | 100.0% (162/162) | n/a (0/0 trials) |
| full_system | 0.0% (0/162) | n/a (0/0 trials) |

`detection_only`'s two rates are trivially 0 by construction -- a system with no response layer can never take an unsafe autonomous action or an unnecessary isolation, because it never takes any action at all. This is a definitional artifact of that baseline, not a safety property, and is reported here rather than omitted so it cannot be mistaken for a measured result.

**Unnecessary-isolation rate could not be measured for this run** (denominator 0/0): this model had zero measured false positives on its held-out split -- see the `false_positive_rate_per_class` entries in `phase13_baseline_comparison.json`, all 0.0 for every attack class. This is a real, honest limitation of the *synthetic* dataset, not a hidden or fabricated result: `synthetic_data.py`'s per-class profiles (module docstring, Phase 3) are Gaussian-separated by construction, cleaner than real network traffic is ever likely to be, so a baseline this easy to classify perfectly leaves no false positives for this metric to measure against. The metric and the comparison logic are real and ready (`app/evaluation/baseline_systems.is_unnecessary_isolation`, unit-tested directly in `app/evaluation/tests/test_baseline_systems.py`); what's missing is a dataset with realistic class overlap to actually exercise it -- the real CICIoMT2024 dataset, once downloadable, is the natural next place to re-run this and get a nonzero denominator.

