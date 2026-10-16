# cybersecurity

L3 of the architecture. The detection engine: trained offline against CICIoMT2024
(primary) and WUSTL-EHMS-2020 (secondary, network+clinical fusion) using baseline
models (Random Forest / XGBoost) before any deep-learning model is considered. At
runtime, scores the simulator's live event stream and emits structured
`DetectionEvent` records — the one piece of evidence downstream agents are allowed
to treat as ground truth.

Status: built. Two separate pipelines, deliberately not interchangeable:

- **Synthetic / runtime pipeline** (`synthetic_data.py`, `training.py`,
  `feature_extraction.py`, `detection_service.py`): a 15-feature schema the IoMT
  simulator can actually produce, used by the live `/detections` path and the
  Phase 13 ablation harness.
- **Real CICIoMT2024 pipeline** (`ciciomt2024.py`, `train_ciciomt2024.py`): the
  dataset's own 45 flow features, official capture-level train/test split,
  19-class / 6-family / binary views. Reported in
  `evaluation/ciciomt2024_results.md`. Models trained here need the 45 real
  features and cannot be fed by the simulator's proxy features.

**Final-completion additions.**

- `real_flow_detection.py` — `RealFlowDetectionService` scores real 45-feature
  CICIoMT2024 rows with the trained XGBoost model and emits the same
  `DetectionEvent` as the proxy pipeline (19-class label → family →
  `AttackCategory`; benign produces no event). Exposed as
  `POST /detections/score-flows`. It validates the model's recorded feature
  columns against the 45 and rejects missing or non-finite values rather than
  imputing them.
- `calibration.py` — temperature scaling (one scalar, fitted by minimum NLL on
  validation) and expected calibration error. It changes the confidence's scale,
  not which rows are misclassified.
- `ciciomt2024.py` gained `cap_rows_per_class` and `split_train_validation`
  (whole last capture held out for multi-capture classes; a contiguous tail block
  with a gap for single-capture classes, whose validation is therefore optimistic).
