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
