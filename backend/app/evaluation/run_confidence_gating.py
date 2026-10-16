"""Does detector confidence make autonomous response safer to grant? A sweep over
a confidence gate on the real CICIoMT2024 detector.

Motivation: `evaluation/real_data_comparison.md` showed `full_system` never acts
unsafely on a high-stakes device, but autonomously isolates a device on about
half of the detector's benign false alarms (the Policy Engine routes on impact
and patient dependency only, never on how sure the detector was). This script
measures a simple fix before anyone touches the Policy Engine: send an
autonomous action to human approval when detector confidence is below a
threshold tau (`decide_full_system_confidence_gated`, experiment-only).

Protocol, fixed before looking at results
-----------------------------------------
* tau grid: 0.6 (the runtime detection threshold, so the gate is a no-op and
  must reproduce the earlier `full_system` numbers exactly), 0.7, 0.8, 0.9,
  0.95, 0.99, 0.999. The whole grid is reported; no "best" tau is selected here.
* Same 1,614,182 test rows, same 5 context seeds and the same per-chunk context
  sampling as `run_real_data_comparison.py`.
* Because the gate can only turn an autonomous action into an approval request,
  the unsafe-action rate must stay 0; the run asserts it.
* Choosing a tau is a calibration decision that needs held-out *validation*
  data, not the test split this sweep is scored on. Reading a tau off these
  curves and deploying it would be tuning on test; this report is evidence that
  a gate is worth building and calibrating, not a recommended value.

Efficiency: the gate only ever removes autonomous executions, so one
`decide_full_system` pass per trial gives the baseline decision, and every tau
is then evaluated with vector operations. A random sample of trials is
re-checked against the real `decide_full_system_confidence_gated` function to
prove the vectorised path is equivalent.

Usage (from `backend/`):
    python -m app.evaluation.run_confidence_gating --data-dir /path/to/iomt
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.cybersecurity.ciciomt2024 import FEATURE_COLUMNS, LABEL_COLUMN, load_split
from app.cybersecurity.detection_service import DEFAULT_CONFIDENCE_THRESHOLD
from app.evaluation.baseline_systems import (
    decide_full_system,
    decide_full_system_confidence_gated,
    detection_outcome_from_row,
    is_high_stakes,
    sample_device_contexts,
)
from app.evaluation.run_real_data_comparison import harness_label, predict_all
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_MODEL = _REPO_ROOT / "experiments" / "models" / "ciciomt2024_xgboost.joblib"
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "evaluation"
_BASE_CONTEXT_SEED = 2026
TAU_GRID = [0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999]


def baseline_pass(
    true_h: np.ndarray,
    pred_h: np.ndarray,
    conf: np.ndarray,
    *,
    seed: int,
    chunk: int = 100_000,
    gate_conf: np.ndarray | None = None,
) -> dict[str, np.ndarray]:
    """One `decide_full_system` call per trial. Returns per-trial boolean arrays
    (`fired`, `attack`, `high_stakes`, `executed`) plus `conf`.

    `conf` decides whether a detection fires (the runtime's raw confidence).
    `gate_conf`, if given, is what the confidence gate is later applied to (for
    example temperature-calibrated confidence); it defaults to `conf`."""
    risk_model, policy_engine = RuleBasedRiskModel(), PolicyEngine()
    n = len(true_h)
    fired = np.zeros(n, dtype=bool)
    executed = np.zeros(n, dtype=bool)
    high = np.zeros(n, dtype=bool)
    for chunk_idx, start in enumerate(range(0, n, chunk)):
        end = min(start + chunk, n)
        contexts = sample_device_contexts(end - start, seed=seed + chunk_idx)
        for j, i in enumerate(range(start, end)):
            detection = detection_outcome_from_row(str(true_h[i]), str(pred_h[i]), float(conf[i]))
            context = contexts[j]
            high[i] = is_high_stakes(context)
            fired[i] = detection.fired
            if detection.fired:
                decision = decide_full_system(
                    detection, context, f"EVAL-gate-{i}", risk_model=risk_model, policy_engine=policy_engine
                )
                executed[i] = decision.executed_action is not None
    return {
        "fired": fired,
        "attack": true_h != "unknown",
        "high_stakes": high,
        "executed": executed,
        "conf": conf if gate_conf is None else gate_conf,
    }


def metrics_for_tau(p: dict[str, np.ndarray], tau: float) -> dict[str, Any]:
    fired, attack, high, executed, conf = p["fired"], p["attack"], p["high_stakes"], p["executed"], p["conf"]
    gated = executed & (conf >= tau)
    fp = fired & ~attack
    tp = fired & attack
    removed = executed & ~gated

    def rate(num: int, den: int) -> float | None:
        return num / den if den else None

    return {
        "tau": tau,
        "unnecessary_isolation": {
            "numerator": int((fp & gated).sum()),
            "denominator": int(fp.sum()),
            "rate": rate(int((fp & gated).sum()), int(fp.sum())),
        },
        "unsafe_autonomous_action": {
            "numerator": int((attack & high & gated).sum()),
            "denominator": int((attack & high).sum()),
            "rate": rate(int((attack & high & gated).sum()), int((attack & high).sum())),
        },
        "real_attack_autonomous_retention": {
            "numerator": int((tp & gated).sum()),
            "denominator": int((tp & executed).sum()),
            "rate": rate(int((tp & gated).sum()), int((tp & executed).sum())),
        },
        "approvals_added": {
            "total": int(removed.sum()),
            "of_which_real_attacks": int((removed & attack).sum()),
            "of_which_false_alarms": int((removed & ~attack).sum()),
            "per_1000_detections": 1000 * int(removed.sum()) / max(int(fired.sum()), 1),
        },
    }


def verify_equivalence(
    true_h: np.ndarray, pred_h: np.ndarray, conf: np.ndarray, *, seed: int, taus: list[float], n: int = 3000
) -> int:
    """Re-derive `n` random trials through the real gated function and compare with the vectorised
    rule. Raises on any mismatch; returns the number of trials compared."""
    rng = np.random.default_rng(0)
    idx = np.sort(rng.choice(len(true_h), size=n, replace=False))
    contexts = sample_device_contexts(n, seed=seed)
    risk_model, policy_engine = RuleBasedRiskModel(), PolicyEngine()
    for j, i in enumerate(idx):
        detection = detection_outcome_from_row(str(true_h[i]), str(pred_h[i]), float(conf[i]))
        base = decide_full_system(
            detection, contexts[j], "EQ", risk_model=risk_model, policy_engine=policy_engine
        )
        for tau in taus:
            gated = decide_full_system_confidence_gated(
                detection,
                contexts[j],
                "EQ",
                risk_model=risk_model,
                policy_engine=policy_engine,
                min_autonomous_confidence=tau,
            )
            expected = base.executed_action is not None and float(conf[i]) >= tau
            if (gated.executed_action is not None) != expected:
                raise AssertionError(f"vectorised gate disagrees with the real function: row {i}, tau {tau}")
    return n


def _spread(vals: list[float | None]) -> dict[str, float | None]:
    xs = [v for v in vals if v is not None]
    return (
        {"mean": float(np.mean(xs)), "min": float(min(xs)), "max": float(max(xs))}
        if xs
        else {
            "mean": None,
            "min": None,
            "max": None,
        }
    )


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _cell(stat: dict[str, float | None]) -> str:
    if stat["mean"] is None:
        return "n/a"
    return f"{_pct(stat['mean'])} ({_pct(stat['min'])} to {_pct(stat['max'])})"


def render_markdown(report: dict[str, Any]) -> str:
    c = report["confidence_separation"]
    lines = [
        "# Confidence gate sweep on the real CICIoMT2024 detector",
        "",
        f"Generated {report['generated_at']}. Experiment-only: the gate "
        "(`decide_full_system_confidence_gated`) is not part of the Policy Engine. Scored on all "
        f"{report['trials']:,} official test rows, {len(report['seeds'])} device-context seeds "
        "(cells: mean, then min to max across seeds). The tau grid was fixed before running and "
        "is reported in full.",
        "",
        "## Does confidence separate real attacks from false alarms?",
        "",
        f"Among detections that fire (confidence >= {report['detection_threshold']}): "
        f"{c['true_positives']:,} real attacks vs {c['false_positives']:,} false alarms. "
        f"Median confidence: real attacks {c['tp_median']:.4f}, false alarms {c['fp_median']:.4f}. "
        f"AUROC of confidence for telling them apart: {c['auroc']:.4f}. "
        f"{c['fp_share_predicted_arp_spoofing']:.1%} of the false alarms were predicted as "
        "ARP spoofing, the detector's weakest class (see `ciciomt2024_results.md`).",
        "",
        "## Gate sweep",
        "",
        "| tau | Unnecessary isolation (of false alarms) | Unsafe autonomous action | "
        "Real-attack autonomy retained | Extra approvals per 1,000 detections |",
        "|---|---|---|---|---|",
    ]
    for row in report["summary"]:
        lines.append(
            f"| {row['tau']} | {_cell(row['unnecessary_isolation'])} | "
            f"{_cell(row['unsafe_autonomous_action'])} | {_cell(row['real_attack_autonomous_retention'])} | "
            f"{row['approvals_per_1000']['mean']:.2f} |"
        )
    lines += [
        "",
        f"- tau = {report['tau_grid'][0]} equals the runtime detection threshold, so the gate does nothing "
        "and reproduces the earlier `full_system` numbers (a built-in consistency check).",
        "- *Unnecessary isolation*: share of the detector's false alarms where the system still "
        f"acted on its own. Denominator: {report['per_seed'][0][0]['unnecessary_isolation']['denominator']:,}"
        " "
        "false alarms (same rows every seed), a small sample.",
        "- *Real-attack autonomy retained*: of the real attacks the system would have handled "
        "autonomously without the gate, the share it still handles autonomously. The rest wait "
        "for a human, which is the cost of the gate.",
        "- *Unsafe autonomous action* must stay 0.0%: the gate only ever removes autonomous actions.",
        "",
        "## Reading this honestly",
        "",
        "- The curves show confidence is informative here; they do **not** pick a deployable tau. "
        "Calibrating tau needs validation data held out from both training and this test split.",
        "- Real-attack confidences are almost all ~1.0 because the volumetric floods are easy; "
        "whether that holds on another network or against evasive traffic is untested.",
        "- XGBoost's softmax confidence is not calibrated; a calibrated probability would make the "
        "threshold interpretable.",
        "- The false-alarm sample is small (one detector, one test capture set) and concentrated "
        "in one predicted class, so the gate's benefit may largely reflect that class's weakness.",
        f"- Vectorised path re-checked against the real gated function on {report['equivalence_checked']:,} "
        "random trials x every tau: no mismatches.",
        "",
    ]
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.time()
    if not args.model_path.exists():
        raise FileNotFoundError(f"{args.model_path} not found; run train_ciciomt2024 first.")
    model = joblib.load(args.model_path)
    test = load_split(args.data_dir, "test")
    true19 = test[LABEL_COLUMN].to_numpy(dtype=object)
    X = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del test
    pred19, conf = predict_all(model, X)
    del X
    true_h = np.array([harness_label(x) for x in true19], dtype=object)
    pred_h = np.array([harness_label(x) for x in pred19], dtype=object)
    print(f"[{time.time() - t0:5.0f}s] predictions ready for {len(true_h):,} rows", flush=True)

    fired = (pred_h != "unknown") & (conf >= DEFAULT_CONFIDENCE_THRESHOLD)
    attack = true_h != "unknown"
    tp_mask, fp_mask = fired & attack, fired & ~attack
    from sklearn.metrics import roc_auc_score

    auroc = float(
        roc_auc_score(
            np.concatenate([np.ones(int(tp_mask.sum())), np.zeros(int(fp_mask.sum()))]),
            np.concatenate([conf[tp_mask], conf[fp_mask]]),
        )
    )
    fp_classes = Counter(pred19[fp_mask])
    separation = {
        "true_positives": int(tp_mask.sum()),
        "false_positives": int(fp_mask.sum()),
        "tp_median": float(np.median(conf[tp_mask])),
        "fp_median": float(np.median(conf[fp_mask])),
        "fp_confidence_quantiles_5_25_50_75_95": [
            float(q) for q in np.quantile(conf[fp_mask], [0.05, 0.25, 0.5, 0.75, 0.95])
        ],
        "auroc": auroc,
        "fp_predicted_class_counts": dict(fp_classes.most_common()),
        "fp_share_predicted_arp_spoofing": fp_classes.get("ARP_Spoofing", 0) / max(int(fp_mask.sum()), 1),
    }

    seeds = [_BASE_CONTEXT_SEED + 7919 * i for i in range(args.n_seeds)]
    per_seed: list[list[dict[str, Any]]] = []
    for i, seed in enumerate(seeds):
        p = baseline_pass(true_h, pred_h, conf, seed=seed)
        rows = [metrics_for_tau(p, tau) for tau in TAU_GRID]
        for r in rows:
            assert r["unsafe_autonomous_action"]["numerator"] == 0, "gate produced an unsafe action"
        per_seed.append(rows)
        print(
            f"[{time.time() - t0:5.0f}s] seed {i + 1}/{len(seeds)}: baseline unnecessary "
            f"{rows[0]['unnecessary_isolation']['numerator']}/"
            f"{rows[0]['unnecessary_isolation']['denominator']}, "
            f"at tau 0.95 {rows[4]['unnecessary_isolation']['numerator']}",
            flush=True,
        )

    checked = verify_equivalence(true_h, pred_h, conf, seed=seeds[0], taus=TAU_GRID)

    summary = []
    for t_idx, tau in enumerate(TAU_GRID):
        rows = [s[t_idx] for s in per_seed]
        summary.append(
            {
                "tau": tau,
                "unnecessary_isolation": _spread([r["unnecessary_isolation"]["rate"] for r in rows]),
                "unsafe_autonomous_action": _spread([r["unsafe_autonomous_action"]["rate"] for r in rows]),
                "real_attack_autonomous_retention": _spread(
                    [r["real_attack_autonomous_retention"]["rate"] for r in rows]
                ),
                "approvals_per_1000": _spread([r["approvals_added"]["per_1000_detections"] for r in rows]),
            }
        )

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "trials": int(len(true_h)),
        "detection_threshold": DEFAULT_CONFIDENCE_THRESHOLD,
        "tau_grid": TAU_GRID,
        "seeds": seeds,
        "confidence_separation": separation,
        "equivalence_checked": checked,
        "per_seed": per_seed,
        "summary": summary,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "confidence_gating.json").write_text(json.dumps(report, indent=2, default=float))
    (args.output_dir / "confidence_gating.md").write_text(render_markdown(report))
    print(f"[{time.time() - t0:5.0f}s] wrote reports to {args.output_dir}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, default=_DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--n-seeds", type=int, default=5)
    args = parser.parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
