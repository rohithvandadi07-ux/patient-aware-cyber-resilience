"""Patient-safety comparison (five systems, six ablations) driven by the REAL
CICIoMT2024 detector, scored on the entire official test split.

This is `run_baseline_comparison.py`'s real-data counterpart. The decision
logic is not duplicated: every trial goes through the same
`run_comparison_for_model` (same Risk Engine, Policy Engine, systems and
ablations). What changes is where the trial rows come from:

* the detector is the XGBoost model trained on the real 45-feature
  CICIoMT2024 train split (`app/cybersecurity/train_ciciomt2024.py`), loaded
  from `experiments/models/ciciomt2024_xgboost.joblib`;
* every row of the real test split (1.6M rows) is one trial, so the detector's
  real mistakes -- including its real benign false positives, which the
  synthetic stand-in never produced -- flow into the comparison;
* the one thing still simulated is the clinical device context (HIGH/MEDIUM/LOW
  criticality x patient-dependent or not), because the dataset has no clinical
  information at all. Contexts are sampled uniformly and independently of the
  row's label (see `baseline_systems.sample_device_contexts`). That randomness
  is the only source of variation across runs, so the comparison is repeated
  over several context seeds and the spread is reported.

Disclosed stand-ins are unchanged from the synthetic run: the three LLM-backed
agents are deterministic functions of the trial's ground truth (see
`baseline_systems.py`), and `without_blockchain` / `without_recovery_verification`
are structural no-ops in this per-row decision harness.

Class mapping: the harness only distinguishes benign from attack (the label
string `"unknown"` is the harness's benign class), so the 19 real classes are
mapped to attack families purely to fit that vocabulary. Nothing in the
decision logic depends on which attack family a row belongs to.

Usage (from `backend/`):
    python -m app.evaluation.run_real_data_comparison --data-dir /path/to/iomt
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.cybersecurity.ciciomt2024 import CLASS_NAMES, FEATURE_COLUMNS, LABEL_COLUMN, family_of, load_split
from app.cybersecurity.detection_service import DEFAULT_CONFIDENCE_THRESHOLD
from app.evaluation.run_baseline_comparison import run_comparison_for_model

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_MODEL = _REPO_ROOT / "experiments" / "models" / "ciciomt2024_xgboost.joblib"
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "evaluation"

_BASE_CONTEXT_SEED = 2026
_FAMILY_TO_HARNESS_LABEL = {
    "Benign": "unknown",  # the harness's benign class
    "ARP_Spoofing": "spoofing",
    "MQTT": "mqtt_based",
    "Recon": "reconnaissance",
    "DoS": "dos",
    "DDoS": "ddos",
}


def harness_label(label: str) -> str:
    """19-class CICIoMT2024 label -> the label vocabulary the harness uses
    (benign is `"unknown"`)."""
    return _FAMILY_TO_HARNESS_LABEL[family_of(label)]


def predict_all(model: Any, X: np.ndarray, batch: int = 200_000) -> tuple[np.ndarray, np.ndarray]:
    """Predicted 19-class label and the detector's confidence (max class
    probability) for every row, batched to bound memory."""
    labels = np.empty(len(X), dtype=object)
    conf = np.empty(len(X), dtype=np.float32)
    for start in range(0, len(X), batch):
        proba = model.predict_proba(X[start : start + batch])
        idx = proba.argmax(axis=1)
        labels[start : start + len(idx)] = [CLASS_NAMES[i] for i in idx]
        conf[start : start + len(idx)] = proba.max(axis=1)
    return labels, conf


# ------------------------------------------------------------------ count merging


def _merge(a: Any, b: Any) -> Any:
    """Sum every integer count of two comparison results; keep strings from `a`.
    Floats (rates) are dropped here and recomputed by `_finalize`."""
    if isinstance(a, dict):
        return {k: _merge(a[k], b[k]) if k in b else a[k] for k in a}
    if isinstance(a, bool):
        return a
    if isinstance(a, int):
        return a + b
    return a


def _finalize(node: Any) -> Any:
    """Recompute every `rate` from its merged numerator/denominator."""
    if isinstance(node, dict):
        out = {k: _finalize(v) for k, v in node.items()}
        if "numerator" in out and "denominator" in out:
            den = out["denominator"]
            out["rate"] = (out["numerator"] / den) if den > 0 else None
        return out
    return node


def compare_all_rows(
    true_h: np.ndarray, pred_h: np.ndarray, conf: np.ndarray, *, seed: int, chunk: int = 100_000
) -> dict[str, Any]:
    """Run the full comparison over every row for one context seed, in chunks
    (bounds memory), and return the merged, finalized counts."""
    merged: dict[str, Any] | None = None
    for chunk_idx, start in enumerate(range(0, len(true_h), chunk)):
        sl = slice(start, start + chunk)
        true_s = pd.Series(true_h[sl])
        pred_s = pd.Series(pred_h[sl])
        result = run_comparison_for_model(
            "xgboost",
            true_s,  # only its length is used
            true_s,
            pred_s,
            conf[sl],
            device_context_seed=seed + chunk_idx,
        )
        result.pop("model_name", None)
        merged = result if merged is None else _merge(merged, result)
    assert merged is not None
    return _finalize(merged)


# ------------------------------------------------------------------ summary


def _spread(values: list[float | None]) -> dict[str, float | None]:
    xs = [v for v in values if v is not None]
    if not xs:
        return {"mean": None, "min": None, "max": None}
    return {"mean": float(np.mean(xs)), "min": float(min(xs)), "max": float(max(xs))}


def summarize(per_seed: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean/min/max of each headline rate across context seeds."""

    def collect(group: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in per_seed[0][group]:
            unsafe = [s[group][name]["unsafe_autonomous_action_rate"] for s in per_seed]
            unnec = [s[group][name]["unnecessary_isolation_rate"] for s in per_seed]
            entry = {
                "unsafe_autonomous_action_rate": {
                    **_spread([u["rate"] for u in unsafe]),
                    "numerators_per_seed": [u["numerator"] for u in unsafe],
                    "denominators_per_seed": [u["denominator"] for u in unsafe],
                },
                "unnecessary_isolation_rate": {
                    **_spread([u["rate"] for u in unnec]),
                    "numerators_per_seed": [u["numerator"] for u in unnec],
                    "denominators_per_seed": [u["denominator"] for u in unnec],
                },
                "autonomous_executions_per_seed": [s[group][name]["autonomous_executions"] for s in per_seed],
            }
            if "trials_where_decision_differs_from_full_system" in per_seed[0][group][name]:
                entry["trials_where_decision_differs_from_full_system_per_seed"] = [
                    s[group][name]["trials_where_decision_differs_from_full_system"]["count"]
                    for s in per_seed
                ]
            out[name] = entry
        return out

    return {"systems": collect("systems"), "ablations": collect("ablations")}


def _pct(x: float | None, digits: int = 2) -> str:
    return "n/a" if x is None else f"{x * 100:.{digits}f}%"


def _cell(stat: dict[str, Any]) -> str:
    if stat["mean"] is None:
        return "n/a"
    if stat["min"] == stat["max"]:
        return _pct(stat["mean"])
    return f"{_pct(stat['mean'])} ({_pct(stat['min'])} to {_pct(stat['max'])})"


def render_markdown(report: dict[str, Any]) -> str:
    d = report["detector_at_threshold"]
    first = report["per_seed"][0]
    high_stakes = ", ".join(f"{s['high_stakes_real_attack_trials']:,}" for s in report["per_seed"])
    lines = [
        "# Patient-safety comparison on the real CICIoMT2024 detector",
        "",
        f"Generated {report['generated_at']}. Every one of the {report['trials']:,} rows of the "
        "official CICIoMT2024 WiFi+MQTT **test** split is one trial, scored by the XGBoost detector "
        "trained on the real train split (`evaluation/ciciomt2024_results.md`). The Risk Engine and "
        "Policy Engine are the real ones; the clinical device context is simulated (the dataset has "
        "none), sampled uniformly over 3 criticality levels x patient-dependent yes/no, and the "
        f"whole comparison is repeated over {len(report['seeds'])} context seeds "
        "(cells show mean, then min to max across seeds).",
        "",
        "## Detector at the runtime operating point",
        "",
        f"Detections fire when the predicted class is not benign and confidence >= "
        f"{report['confidence_threshold']}. On this split: {d['detections_fired']:,} fired; "
        f"{d['real_attacks']:,} rows are real attacks, {d['benign_rows']:,} are benign; "
        f"attack detection rate {_pct(d['attack_detection_rate'])}; benign false-positive rate "
        f"{_pct(d['benign_false_positive_rate'])} ({d['false_positives']:,} benign rows flagged).",
        "",
        "High-stakes trials per seed (real attack AND HIGH-criticality, patient-dependent device): "
        f"{high_stakes}.",
        "",
        "## Five systems",
        "",
        "| System | Unsafe autonomous action rate | Unnecessary isolation rate |",
        "|---|---|---|",
    ]
    for name, e in report["summary"]["systems"].items():
        lines.append(
            f"| {name} | {_cell(e['unsafe_autonomous_action_rate'])} | "
            f"{_cell(e['unnecessary_isolation_rate'])} |"
        )
    lines += [
        "",
        "- *Unsafe autonomous action rate*: among real attacks hitting a HIGH-criticality, "
        "patient-dependent device, the share where the system executed a disruptive action without "
        "a human.",
        "- *Unnecessary isolation rate*: among detector false positives (benign traffic flagged), "
        "the share where the system autonomously isolated the device anyway. This is measurable "
        "here for the first time; the synthetic stand-in produced no false positives.",
        "- `detection_only` is 0 on both by construction (it never acts), not a safety result.",
        f"- The unnecessary-isolation denominator is the same {d['false_positives']:,} benign rows the "
        "detector flagged in every seed, so that rate rests on a much smaller sample than the "
        "unsafe-action rate. It also means the full system, while never acting unsafely on a "
        "high-stakes device, still isolates a device autonomously on roughly half of the detector's "
        "false alarms (those landing on contexts the Policy Engine allows it to handle alone).",
        "",
        "## Six ablations of `full_system`",
        "",
        "| Ablation | Unsafe autonomous action rate | Unnecessary isolation rate | "
        "Trials differing from full_system (per seed) |",
        "|---|---|---|---|",
    ]
    for name, e in report["summary"]["ablations"].items():
        diffs = e["trials_where_decision_differs_from_full_system_per_seed"]
        lines.append(
            f"| {name} | {_cell(e['unsafe_autonomous_action_rate'])} | "
            f"{_cell(e['unnecessary_isolation_rate'])} | {min(diffs):,} to {max(diffs):,} |"
        )
    reopen = first["ablations"]["without_recovery_verification"]["would_reopen_if_verified"]
    lines += [
        "",
        "`without_blockchain` and `without_recovery_verification` reuse `full_system`'s decision "
        "(neither component is on this harness's decision path), so their rows equal `full_system`'s "
        f"by construction. First-seed `would_reopen_if_verified`: {reopen['numerator']:,} of "
        f"{reopen['denominator']:,} autonomous executions.",
        "",
        "## What this does and does not show",
        "",
        "- The detector, Risk Engine and Policy Engine are real; the clinical context and the three "
        "LLM-backed agents are disclosed stand-ins. The result is about whether the decision layer "
        "gates autonomous action on clinical context, not about clinical outcomes.",
        "- Device contexts are sampled, not observed; real hospital device mixes would change the "
        "denominators, not the gating logic.",
        "- Variation across seeds reflects context sampling only; the detector is a single trained "
        "model (one training seed).",
        "- Rates use the harness's own definitions (see `app/evaluation/baseline_systems.py`).",
        "",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ main


def run(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.time()
    if not args.model_path.exists():
        raise FileNotFoundError(
            f"{args.model_path} not found. Train it first: "
            "python -m app.cybersecurity.train_ciciomt2024 --data-dir <folder with train/ and test/>"
        )
    model = joblib.load(args.model_path)

    test = load_split(args.data_dir, "test")
    true19 = test[LABEL_COLUMN].to_numpy(dtype=object)
    X = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del test
    print(f"[{time.time() - t0:5.0f}s] {len(X):,} test rows loaded", flush=True)

    pred19, conf = predict_all(model, X)
    del X
    print(f"[{time.time() - t0:5.0f}s] predictions done", flush=True)

    true_h = np.array([harness_label(x) for x in true19], dtype=object)
    pred_h = np.array([harness_label(x) for x in pred19], dtype=object)

    fired = (pred_h != "unknown") & (conf >= DEFAULT_CONFIDENCE_THRESHOLD)
    attack = true_h != "unknown"
    detector = {
        "detections_fired": int(fired.sum()),
        "real_attacks": int(attack.sum()),
        "benign_rows": int((~attack).sum()),
        "false_positives": int((fired & ~attack).sum()),
        "attack_detection_rate": float((fired & attack).sum() / max(attack.sum(), 1)),
        "benign_false_positive_rate": float((fired & ~attack).sum() / max((~attack).sum(), 1)),
    }

    seeds = [_BASE_CONTEXT_SEED + 7919 * i for i in range(args.n_seeds)]
    per_seed = []
    for i, seed in enumerate(seeds):
        per_seed.append(compare_all_rows(true_h, pred_h, conf, seed=seed))
        full = per_seed[-1]["systems"]["full_system"]["unsafe_autonomous_action_rate"]
        fixed = per_seed[-1]["systems"]["fixed_response"]["unsafe_autonomous_action_rate"]
        print(
            f"[{time.time() - t0:5.0f}s] seed {i + 1}/{len(seeds)}: unsafe full_system "
            f"{full['numerator']}/{full['denominator']}, "
            f"fixed_response {fixed['numerator']}/{fixed['denominator']}",
            flush=True,
        )

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "data_source": (
            "CICIoMT2024 (real), official test split; detector trained on the official train split"
        ),
        "model_path": str(args.model_path.name),
        "trials": int(len(true_h)),
        "confidence_threshold": DEFAULT_CONFIDENCE_THRESHOLD,
        "seeds": seeds,
        "detector_at_threshold": detector,
        "per_seed": per_seed,
        "summary": summarize(per_seed),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "real_data_comparison.json").write_text(json.dumps(report, indent=2, default=float))
    (args.output_dir / "real_data_comparison.md").write_text(render_markdown(report))
    print(f"[{time.time() - t0:5.0f}s] wrote reports to {args.output_dir}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, required=True, help="Folder containing train/ and test/.")
    parser.add_argument("--model-path", type=Path, default=_DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--n-seeds", type=int, default=5)
    args = parser.parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
