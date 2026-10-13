# notebooks

Exploratory dataset and model analysis only. Nothing here is production logic —
anything a notebook proves useful gets turned into real code under `backend/app/`
or `experiments/`, not imported from here.

## `evaluation_comparison.ipynb`

Loads `evaluation/phase13_baseline_comparison.json` — the real report
`backend/app/evaluation/run_baseline_comparison.py` produces — and
reproduces its headline finding as a table and a bar chart: the
`unsafe_autonomous_action_rate` for each system (`detection_only`,
`fixed_response`, `full_system`) and each trained model
(`random_forest`, `xgboost`), on trials where a real attack hit a
HIGH-criticality, patient-dependent device.

Run it:

```bash
pip install jupyter pandas matplotlib   # not backend dependencies; only this notebook needs them
jupyter notebook notebooks/evaluation_comparison.ipynb   # run from the repo root
```

**Verified, not just written**: actually executed end to end with
`nbclient` against this repo's real `evaluation/phase13_baseline_comparison.json`
while this notebook was authored — the committed copy's outputs (the table
and chart) are real, not hand-typed placeholders. If you re-run it
yourself, the numbers may differ from what's shown if `evaluation/
phase13_baseline_comparison.json` has been regenerated since (its own
`generated_at` field says when); re-running
`run_baseline_comparison.py` first refreshes it (see
`docs/reproducibility.md`).

The notebook's first cell discloses the same thing `docs/
limitations-and-ethics.md` §3 does: every number in that report is computed
against the synthetic stand-in dataset, not real CICIoMT2024 data.
