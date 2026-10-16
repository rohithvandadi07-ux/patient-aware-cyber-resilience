# experiments

Baseline and ablation run configs for the five-system comparison (detection-only
through full patient-aware system) and the seven ablations described in the
architecture specification, Section 18. Trained model artifacts live in
`experiments/models/`, versioned by filename plus a metadata JSON — not committed to
git (large binaries don't belong in the repo).

Status: Phase 13 partial. The detection-only vs. full-system comparison (the
Phase 13 gate's literal minimum) is implemented and has real reported
numbers — see `backend/app/evaluation/` for the code and `evaluation/` for
the report. That run trains fresh in-process (same established pattern as
`backend/tests/test_lifecycle_integration.py` and `tests/e2e/conftest.py`),
so no artifact needs to exist in `experiments/models/` for it to work; this
directory stays empty-but-ready for whichever run config actually needs a
persisted artifact (e.g. a real CICIoMT2024 training run, once that dataset
is downloadable).

Not yet done: the `fixed_response` baseline implemented alongside
`full_system` is a minimal naive-policy stand-in needed to make the
comparison non-trivial (see `backend/app/evaluation/baseline_systems.py`'s
docstring), not the complete five-system progression or the seven ablations
Section 18 describes — those remain for a later pass, built only once each
system variant they'd compare is itself real.

## Real CICIoMT2024 artifacts

`python -m app.cybersecurity.train_ciciomt2024` writes
`experiments/models/ciciomt2024_<model>.joblib` (gitignored) and a matching
`ciciomt2024_<model>.metadata.json` (training data, hyper-parameters, class
counts, metrics). The Random Forest artifact is ~436 MB and is not kept in
this repository; regenerate it with the command above (about one minute for
the RF at the default cap).
