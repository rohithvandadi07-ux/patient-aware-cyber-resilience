"""Diagnostics of the shipped CICIoMT2024 XGBoost detector on the full test split.

Nothing is retrained: the shipped model (`ciciomt2024_xgboost.joblib`) scores the
entire official test split (1,614,182 rows) once, and this script derives from
those probabilities:

* the 19 x 19 confusion matrix (counts) and the 6-family one;
* bootstrap 95% confidence intervals (resampling the joint (true, predicted)
  cells with a multinomial draw, which is equivalent to resampling rows) for
  accuracy, macro-F1, attack-detection rate and benign false-positive rate;
* reliability-diagram data (15 equal-width confidence bins) before and after
  temperature scaling with the temperature fitted on validation data by
  `run_calibrated_gating.py` (T = 0.917);
* ROC and precision-recall curves for the binary attack-versus-benign task
  (score = 1 - P(Benign)) with AUC and average precision.

Usage (from `backend/`):
    python -m app.evaluation.run_detector_diagnostics --data-dir /path/to/iomt --model path/to/model.joblib
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

from app.cybersecurity.calibration import apply_temperature, expected_calibration_error
from app.cybersecurity.ciciomt2024 import (
    CLASS_NAMES,
    FAMILY_NAMES,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    family_of,
    load_split,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
K = len(CLASS_NAMES)
BENIGN = 0
TEMPERATURE = 0.917  # fitted on validation data in run_calibrated_gating.py


def metrics_from_confusion(cm: np.ndarray) -> dict[str, float]:
    tp = np.diag(cm).astype(np.float64)
    support = cm.sum(axis=1).astype(np.float64)
    predicted = cm.sum(axis=0).astype(np.float64)
    with np.errstate(divide="ignore", invalid="ignore"):
        prec = np.where(predicted > 0, tp / predicted, 0.0)
        rec = np.where(support > 0, tp / support, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    attack_rows = cm[1:, :].sum()
    flagged_attack = cm[1:, 1:].sum()
    benign_rows = cm[0, :].sum()
    flagged_benign = cm[0, 1:].sum()
    return {
        "accuracy": float(tp.sum() / cm.sum()),
        "macro_f1": float(f1.mean()),
        "attack_detection": float(flagged_attack / attack_rows),
        "benign_fpr": float(flagged_benign / benign_rows),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=_REPO_ROOT / "evaluation" / "detector_diagnostics.json")
    ap.add_argument("--bootstrap", type=int, default=1000)
    args = ap.parse_args()

    model = joblib.load(args.model)
    test = load_split(args.data_dir, "test")
    idx = {c: i for i, c in enumerate(CLASS_NAMES)}
    y = np.array([idx[v] for v in test[LABEL_COLUMN]], dtype=np.int32)
    X = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del test
    proba = np.empty((len(X), K), dtype=np.float32)
    for s in range(0, len(X), 200_000):
        proba[s : s + 200_000] = model.predict_proba(X[s : s + 200_000])
    del X
    pred = proba.argmax(axis=1)

    cm = np.zeros((K, K), dtype=np.int64)
    np.add.at(cm, (y, pred), 1)
    point = metrics_from_confusion(cm)

    # family confusion
    fam_idx = {f: i for i, f in enumerate(FAMILY_NAMES)}
    fmap = np.array([fam_idx[family_of(c)] for c in CLASS_NAMES])
    fcm = np.zeros((len(FAMILY_NAMES), len(FAMILY_NAMES)), dtype=np.int64)
    np.add.at(fcm, (fmap[y], fmap[pred]), 1)

    # bootstrap over the joint cells
    rng = np.random.default_rng(2026)
    flat = cm.ravel().astype(np.float64)
    p_cells = flat / flat.sum()
    boots = {k: [] for k in point}
    for _ in range(args.bootstrap):
        draw = rng.multinomial(int(flat.sum()), p_cells).reshape(K, K)
        m = metrics_from_confusion(draw)
        for k, v in m.items():
            boots[k].append(v)
    ci = {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in boots.items()}

    # reliability
    def reliability(p: np.ndarray) -> dict:
        conf = p.max(axis=1)
        correct = p.argmax(axis=1) == y
        edges = np.linspace(0.0, 1.0, 16)
        bins = []
        for lo, hi in zip(edges[:-1], edges[1:], strict=True):
            sel = (conf > lo) & (conf <= hi)
            n = int(sel.sum())
            bins.append(
                {
                    "lo": float(lo),
                    "hi": float(hi),
                    "n": n,
                    "mean_conf": float(conf[sel].mean()) if n else None,
                    "accuracy": float(correct[sel].mean()) if n else None,
                }
            )
        return {"ece": float(expected_calibration_error(conf, correct)), "bins": bins}

    rel_raw = reliability(proba)
    rel_cal = reliability(apply_temperature(proba, TEMPERATURE))

    # binary ROC / PR
    is_attack = (y != BENIGN).astype(np.int8)
    score = 1.0 - proba[:, BENIGN]
    fpr, tpr, _ = roc_curve(is_attack, score)
    prec, rec, _ = precision_recall_curve(is_attack, score)

    def thin(a: np.ndarray, b: np.ndarray, n: int = 400) -> list[list[float]]:
        sel = np.unique(np.linspace(0, len(a) - 1, n).astype(int))
        return [[float(a[i]), float(b[i])] for i in sel]

    # benign recall at several attack-detection operating points
    operating = []
    for target in (0.99, 0.995, 0.999, 0.9995):
        j = int(np.searchsorted(tpr, target))
        j = min(j, len(tpr) - 1)
        operating.append({"attack_detection": float(tpr[j]), "benign_fpr": float(fpr[j])})

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "test_rows": int(len(y)),
        "class_names": CLASS_NAMES,
        "family_names": FAMILY_NAMES,
        "confusion_matrix": cm.tolist(),
        "family_confusion_matrix": fcm.tolist(),
        "point_estimates": point,
        "bootstrap_95ci": ci,
        "bootstrap_reps": args.bootstrap,
        "temperature": TEMPERATURE,
        "reliability_raw": rel_raw,
        "reliability_calibrated": rel_cal,
        "binary": {
            "roc_auc": float(roc_auc_score(is_attack, score)),
            "average_precision": float(average_precision_score(is_attack, score)),
            "roc_points": thin(fpr, tpr),
            "pr_points": thin(rec, prec),
            "operating_points": operating,
        },
    }
    args.out.write_text(json.dumps(report))
    print(json.dumps({"point": point, "ci": ci, "ece_raw": rel_raw["ece"], "ece_cal": rel_cal["ece"],
                      "auc": report["binary"]["roc_auc"], "ap": report["binary"]["average_precision"],
                      "operating": operating}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
