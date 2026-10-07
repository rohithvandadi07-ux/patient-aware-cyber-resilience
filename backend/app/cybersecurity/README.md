# cybersecurity

L3 of the architecture. The detection engine: trained offline against CICIoMT2024
(primary) and WUSTL-EHMS-2020 (secondary, network+clinical fusion) using baseline
models (Random Forest / XGBoost) before any deep-learning model is considered. At
runtime, scores the simulator's live event stream and emits structured
`DetectionEvent` records — the one piece of evidence downstream agents are allowed
to treat as ground truth.

Status: not started. Phase 3 work.
