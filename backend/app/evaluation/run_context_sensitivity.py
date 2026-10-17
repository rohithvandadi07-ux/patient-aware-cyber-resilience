"""Sensitivity of the patient-safety result to the clinical device mix.

The CICIoMT2024 files carry no clinical information, so the main comparison
(`run_real_data_comparison.py`) samples each trial's device context uniformly
over {HIGH, MEDIUM, LOW} criticality x {patient-dependent, not}. That is one
arbitrary mix. This script asks whether the conclusion depends on it by
re-running the same systems and ablations while changing

* the share of patient-dependent devices (0, 10, 25, 50, 75, 90, 100 %), with the
  criticality mix kept uniform; and
* the share of HIGH-criticality devices (0, 33, 60, 100 %), with patient
  dependency kept at 50 %.

The detector's predictions are those of the shipped model on the official test
split (`preds.npz`: true label, predicted label, confidence). To keep 11
settings affordable the trials are a sample: EVERY detector false positive
(benign row flagged) plus a seeded random sample of the other rows. All reported
quantities are conditional rates (unsafe action among high-stakes real attacks;
unnecessary isolation among false positives; autonomy among fired detections),
so over-representing false positives does not bias them; the sample size behind
each cell is reported.

Usage (from `backend/`):
    python -m app.evaluation.run_context_sensitivity --preds preds.npz --out out.json
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

import app.evaluation.run_baseline_comparison as rbc
from app.evaluation.baseline_systems import DeviceContext, DeviceCriticality
from app.evaluation.run_real_data_comparison import harness_label

DEFAULT_CONFIDENCE_THRESHOLD = 0.6
SYSTEMS = ["fixed_response", "detection_plus_risk_engine", "detection_plus_agentic_ai", "full_system"]
ABLATIONS = ["without_response_impact_assessment"]


def make_sampler(p_dependent: float, p_high: float | None):
    """Context sampler with a given patient-dependent share and (optionally) HIGH share."""

    def sample(n: int, seed: int) -> list[DeviceContext]:
        rng = random.Random(seed)
        crit = list(DeviceCriticality)
        out = []
        for _ in range(n):
            if p_high is None:
                c = rng.choice(crit)
            else:
                others = [x for x in crit if x != DeviceCriticality.HIGH]
                c = DeviceCriticality.HIGH if rng.random() < p_high else rng.choice(others)
            out.append(DeviceContext(device_criticality=c, patient_dependency=rng.random() < p_dependent))
        return out

    return sample


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preds", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--sample", type=int, default=120_000)
    args = ap.parse_args()

    d = np.load(args.preds, allow_pickle=True)
    y, p, conf = d["y"], d["p"], d["conf"]
    fired = (p != "Benign") & (conf >= DEFAULT_CONFIDENCE_THRESHOLD)
    fp = fired & (y == "Benign")
    rng = np.random.default_rng(7)
    others = np.flatnonzero(~fp)
    pick = np.sort(np.concatenate([np.flatnonzero(fp), rng.choice(others, size=args.sample, replace=False)]))
    ys = pd.Series([harness_label(v) for v in y[pick]])
    ps = pd.Series([harness_label(v) for v in p[pick]])
    cs = conf[pick]
    print(f"trials: {len(pick):,} (false positives kept whole: {int(fp.sum()):,})", flush=True)

    settings = []
    for dep in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
        settings.append({"axis": "patient_dependent_share", "value": dep, "p_dep": dep, "p_high": None})
    for hi in (0.0, 1 / 3, 0.6, 1.0):
        settings.append({"axis": "high_criticality_share", "value": hi, "p_dep": 0.5, "p_high": hi})

    results = []
    for s in settings:
        rbc.sample_device_contexts = make_sampler(s["p_dep"], s["p_high"])
        res = rbc.run_comparison_for_model("xgboost", ys, ys, ps, cs, device_context_seed=11)
        row = {"setting": s, "trials": res["trials"], "fired": res["detections_fired"],
               "false_positives": res["false_positives_in_split"],
               "high_stakes_real_attack_trials": res["high_stakes_real_attack_trials"], "systems": {}}
        for name in SYSTEMS:
            m = res["systems"][name]
            row["systems"][name] = _cells(m, res)
        for name in ABLATIONS:
            row["systems"][name] = _cells(res["ablations"][name], res)
        results.append(row)
        f = row["systems"]["full_system"]
        print(f"{s['axis']}={s['value']:.2f}: full unsafe {f['unsafe_num']}/{f['unsafe_den']} "
              f"unnec {f['unnec_num']}/{f['unnec_den']} autonomy {f['autonomy']:.3f}", flush=True)
    payload = {"generated_at": datetime.now(UTC).isoformat(), "results": results}
    args.out.write_text(json.dumps(payload, indent=1))
    return 0


def _cells(m: dict, res: dict) -> dict:
    fired = res["detections_fired"]
    return {
        "unsafe_num": m["unsafe_autonomous_action_rate"]["numerator"],
        "unsafe_den": m["unsafe_autonomous_action_rate"]["denominator"],
        "unnec_num": m["unnecessary_isolation_rate"]["numerator"],
        "unnec_den": m["unnecessary_isolation_rate"]["denominator"],
        "autonomy": m["autonomous_executions"] / fired if fired else None,
        "awaiting": m["awaiting_human_approval"] / fired if fired else None,
    }


if __name__ == "__main__":
    raise SystemExit(main())
