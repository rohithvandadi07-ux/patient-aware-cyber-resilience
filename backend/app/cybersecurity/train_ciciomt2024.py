"""Train and evaluate the detection baselines on the REAL CICIoMT2024 data.

This is the real-data counterpart of `training.py` (which stays pointed at the
synthetic stand-in, because the runtime simulator's feature vector is a
different, 15-column proxy schema -- see `feature_extraction.py`). Here the
models are trained on the dataset's own 45 flow features, with its official
capture-level train/test split, and evaluated on the *entire* official test
split.

What is deliberately NOT done, and why
--------------------------------------
* No random re-split of pooled rows. Rows from one capture are near-duplicates
  of each other, so a random 75/25 split leaks the test set into training and
  inflates every metric. The official split is used unchanged.
* No sampling on the test split. `--max-rows-per-class` (and the RF-specific
  cap) apply to the training data only; every reported number is computed on
  all test rows.
* No hyper-parameter tuning on the test split. Hyper-parameters are fixed up
  front (see `DEFAULT_*` below) and recorded in the metadata, so the reported
  numbers are one honest evaluation, not the best of several peeks.

Why training is capped per class
--------------------------------
Eight of the 19 classes (the TCP/IP DoS and DDoS floods) have 0.4 to 1.6 million
near-identical rows each, against ~700 for the smallest. Training on all 7.0M
rows is slow on a small machine and adds almost no information for the flood
classes, so the training data is capped at `--max-rows-per-class` rows per class
(seeded random sample; small classes are kept whole). Class weights are then
computed on the capped data. This is recorded in the metadata and the report.

Outputs
-------
* `experiments/models/ciciomt2024_<model>.joblib` -- gitignored artifact.
* `experiments/models/ciciomt2024_<model>.metadata.json` -- training data,
  hyper-parameters, class counts and metrics (spec Section 8).
* `evaluation/ciciomt2024_results.json` and `.md` -- the report.

Usage (from `backend/`):
    python -m app.cybersecurity.train_ciciomt2024 --data-dir /path/to/iomt
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier

from app.cybersecurity.ciciomt2024 import (
    CLASS_NAMES,
    FAMILY_NAMES,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    class_counts,
    family_of,
    is_attack,
    load_split,
)

DEFAULT_MAX_ROWS_PER_CLASS = 300_000
DEFAULT_RF_MAX_ROWS_PER_CLASS = 30_000
DEFAULT_XGB = {
    "n_estimators": 150,
    "max_depth": 8,
    "learning_rate": 0.2,
    "tree_method": "hist",
    "max_bin": 256,
    "subsample": 1.0,
    "colsample_bytree": 1.0,
}
DEFAULT_RF = {"n_estimators": 100, "max_depth": None, "min_samples_leaf": 1, "max_features": "sqrt"}


# --------------------------------------------------------------------------- metrics


def _per_class_fpr(cm: np.ndarray) -> list[float]:
    total = cm.sum()
    out = []
    for i in range(cm.shape[0]):
        fp = cm[:, i].sum() - cm[i, i]
        tn = total - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        out.append(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0)
    return out


def multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict[str, Any]:
    """Accuracy, macro/weighted P/R/F1, per-class P/R/F1/support/FPR and the
    confusion matrix, for string label arrays. Every number is measured."""
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    pw, rw, fw, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    fpr = _per_class_fpr(cm)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(np.mean(p)),
        "recall_macro": float(np.mean(r)),
        "f1_macro": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "precision_weighted": float(pw),
        "recall_weighted": float(rw),
        "f1_weighted": float(fw),
        "per_class": {
            lab: {
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f[i]),
                "false_positive_rate": fpr[i],
                "support": int(s[i]),
            }
            for i, lab in enumerate(labels)
        },
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": labels,
    }


def binary_metrics(true_labels: np.ndarray, pred_labels: np.ndarray) -> dict[str, Any]:
    """Attack-vs-benign view derived from the 19-class labels. `positive` =
    attack. The false-positive rate here (benign flagged as attack) is the
    quantity the patient-aware policy evaluation's `unnecessary_isolation_rate`
    needs, and which the synthetic stand-in could not produce (it had zero
    measured false positives)."""
    yt = np.array([is_attack(x) for x in true_labels])
    yp = np.array([is_attack(x) for x in pred_labels])
    tp = int((yt & yp).sum())
    fn = int((yt & ~yp).sum())
    fp = int((~yt & yp).sum())
    tn = int((~yt & ~yp).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "accuracy": (tp + tn) / max(tp + tn + fp + fn, 1),
        "precision": prec,
        "recall_attack_detection_rate": rec,
        "f1": (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0,
        "false_positive_rate_benign_flagged": fp / (fp + tn) if (fp + tn) else 0.0,
        "false_negative_rate_attack_missed": fn / (fn + tp) if (fn + tp) else 0.0,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
    }


def evaluate_all_views(true_labels: np.ndarray, pred_labels: np.ndarray) -> dict[str, Any]:
    """19-class, 6-family and binary views, all derived from the same 19-class
    predictions so they cannot disagree with each other."""
    fam_true = np.array([family_of(x) for x in true_labels])
    fam_pred = np.array([family_of(x) for x in pred_labels])
    return {
        "19_class": multiclass_metrics(true_labels, pred_labels, CLASS_NAMES),
        "6_family": multiclass_metrics(fam_true, fam_pred, FAMILY_NAMES),
        "binary_attack_vs_benign": binary_metrics(true_labels, pred_labels),
    }


# --------------------------------------------------------------------------- training


def _class_weights(y: np.ndarray) -> dict[str, float]:
    present = sorted(set(y.tolist()), key=CLASS_NAMES.index)
    w = compute_class_weight(class_weight="balanced", classes=np.array(present), y=y)
    return dict(zip(present, w.tolist(), strict=True))


def train_xgboost(
    X: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int, n_jobs: int
) -> tuple[XGBClassifier, dict[str, float]]:
    label_to_idx = {c: i for i, c in enumerate(CLASS_NAMES)}
    y_idx = np.array([label_to_idx[v] for v in y], dtype=np.int32)
    weights = _class_weights(y)
    sample_weight = np.array([weights[v] for v in y], dtype=np.float32)
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=len(CLASS_NAMES),
        eval_metric="mlogloss",
        random_state=seed,
        n_jobs=n_jobs,
        **params,
    )
    model.fit(X, y_idx, sample_weight=sample_weight)
    return model, weights


def train_random_forest(
    X: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int, n_jobs: int
) -> tuple[RandomForestClassifier, dict[str, float]]:
    weights = _class_weights(y)
    model = RandomForestClassifier(
        class_weight="balanced", random_state=seed, n_jobs=n_jobs, **params
    )
    model.fit(X, y)
    return model, weights


def predict_labels(model: Any, X: np.ndarray, kind: str, batch: int = 200_000) -> np.ndarray:
    out = np.empty(len(X), dtype=object)
    for start in range(0, len(X), batch):
        chunk = X[start : start + batch]
        if kind == "xgboost":
            idx = model.predict(chunk).astype(int)
            out[start : start + len(chunk)] = [CLASS_NAMES[i] for i in idx]
        else:
            out[start : start + len(chunk)] = model.predict(chunk)
    return out


# --------------------------------------------------------------------------- reporting


def _fmt(x: float) -> str:
    return f"{x:.4f}"


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# CICIoMT2024 (real data) -- detection baselines\n")
    lines.append(
        "Measured on the **entire official test split** "
        f"({report['dataset']['test_rows']:,} rows) of the real CICIoMT2024 WiFi+MQTT "
        "release. Training used the official train split "
        f"({report['dataset']['train_rows_total']:,} rows), capped per class as stated below. "
        "Nothing here is synthetic.\n"
    )
    ds = report["dataset"]
    lines.append("## Setup\n")
    lines.append(f"- Generated: {report['generated_at']}")
    lines.append(f"- Features: {ds['n_features']} (the dataset's own flow features, float32)")
    lines.append(f"- Classes: {len(CLASS_NAMES)}; seed {report['seed']}")
    lines.append(
        f"- Training cap: {ds['max_rows_per_class']:,} rows/class "
        f"(RF: {ds['rf_max_rows_per_class']:,}); test split uncapped"
    )
    lines.append("- Official capture-level split kept; no random re-splitting, no tuning on test\n")

    lines.append("## Summary\n")
    lines.append(
        "| Model | Train rows | Train time (s) | Acc (19-class) | Macro-F1 (19) | "
        "Macro-F1 (6 family) | Attack detection | Benign FPR |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for name, m in report["models"].items():
        v = m["metrics"]
        b = v["binary_attack_vs_benign"]
        lines.append(
            f"| {name} | {m['train_rows']:,} | {m['train_seconds']:.0f} | "
            f"{_fmt(v['19_class']['accuracy'])} | {_fmt(v['19_class']['f1_macro'])} | "
            f"{_fmt(v['6_family']['f1_macro'])} | {_fmt(b['recall_attack_detection_rate'])} | "
            f"{_fmt(b['false_positive_rate_benign_flagged'])} |"
        )
    lines.append("")

    for name, m in report["models"].items():
        v = m["metrics"]
        lines.append(f"## {name}\n")
        lines.append(f"Hyper-parameters: `{json.dumps(m['hyperparameters'])}`\n")
        lines.append("### Per-class (19-class)\n")
        lines.append("| Class | Test support | Precision | Recall | F1 | FPR |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for lab, d in v["19_class"]["per_class"].items():
            lines.append(
                f"| {lab} | {d['support']:,} | {_fmt(d['precision'])} | {_fmt(d['recall'])} | "
                f"{_fmt(d['f1'])} | {d['false_positive_rate']:.5f} |"
            )
        lines.append("")
        f6 = v["6_family"]
        lines.append(
            f"6-family: accuracy {_fmt(f6['accuracy'])}, macro-F1 {_fmt(f6['f1_macro'])}, "
            f"weighted-F1 {_fmt(f6['f1_weighted'])}\n"
        )
        b = v["binary_attack_vs_benign"]
        c = b["confusion"]
        lines.append(
            f"Binary (attack vs benign): detection rate {_fmt(b['recall_attack_detection_rate'])}, "
            f"benign false-positive rate {b['false_positive_rate_benign_flagged']:.5f}, "
            f"precision {_fmt(b['precision'])} "
            f"(TP {c['tp']:,}, FN {c['fn']:,}, FP {c['fp']:,}, TN {c['tn']:,})\n"
        )
    lines.append("## Caveats\n")
    lines.append(
        "- Random Forest was trained on a smaller per-class cap than XGBoost "
        f"({ds['rf_max_rows_per_class']:,} vs {ds['max_rows_per_class']:,} rows) to fit this run's "
        "compute budget, so the XGBoost-vs-RF gap mixes model and training-data differences."
    )
    lines.append("- One seed, one run: no confidence intervals and no variance across seeds.")
    lines.append(
        "- The official test captures come from the same testbed as training; robustness to "
        "other networks or devices is not measured here."
    )
    lines.append(
        "- Hyper-parameters were fixed before the run and not tuned on the test split. "
        "Features are float32."
    )
    lines.append(
        "- Numbers are not claimed to be directly comparable to published results "
        "(different training subsets, metric definitions and averaging may apply)."
    )
    lines.append("")
    lines.append("## Training class counts\n")
    lines.append("| Class | Official train rows | Used for XGBoost | Test rows |")
    lines.append("|---|---:|---:|---:|")
    for lab in CLASS_NAMES:
        lines.append(
            f"| {lab} | {ds['train_class_counts'][lab]:,} | {ds['train_class_counts_used'][lab]:,} | "
            f"{ds['test_class_counts'][lab]:,} |"
        )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- main


def run(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.time()
    print(f"[{time.time() - t0:6.0f}s] loading official splits from {args.data_dir}", flush=True)
    train_full = load_split(args.data_dir, "train")
    test = load_split(args.data_dir, "test")
    train_counts = class_counts(train_full)
    test_counts = class_counts(test)
    print(f"[{time.time() - t0:6.0f}s] train {len(train_full):,} rows, test {len(test):,} rows", flush=True)

    X_test = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_test = test[LABEL_COLUMN].to_numpy(dtype=object)
    del test

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": args.seed,
        "dataset": {
            "name": "CICIoMT2024 (WiFi and MQTT), official pre-extracted CSVs",
            "n_features": len(FEATURE_COLUMNS),
            "feature_columns": FEATURE_COLUMNS,
            "train_rows_total": int(len(train_full)),
            "test_rows": int(len(y_test)),
            "max_rows_per_class": args.max_rows_per_class,
            "rf_max_rows_per_class": args.rf_max_rows_per_class,
            "train_class_counts": train_counts,
            "test_class_counts": test_counts,
        },
        "models": {},
    }

    out_dir: Path = args.models_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    plans = []
    if "xgboost" in args.models:
        plans.append(
            ("xgboost", args.max_rows_per_class, {**DEFAULT_XGB, "n_estimators": args.xgb_n_estimators})
        )
    if "random_forest" in args.models:
        plans.append(
            (
                "random_forest",
                args.rf_max_rows_per_class,
                {**DEFAULT_RF, "n_estimators": args.rf_n_estimators},
            )
        )

    for name, cap, params in plans:
        rng = np.random.default_rng(args.seed)
        parts = []
        for _, idx in train_full.groupby(LABEL_COLUMN, sort=False).indices.items():
            if len(idx) > cap:
                idx = rng.choice(idx, size=cap, replace=False)
            parts.append(np.sort(idx))
        sel = np.concatenate(parts)
        X = train_full[FEATURE_COLUMNS].to_numpy(dtype=np.float32)[sel]
        y = train_full[LABEL_COLUMN].to_numpy(dtype=object)[sel]
        used = {lab: int((y == lab).sum()) for lab in CLASS_NAMES}
        if name == "xgboost":
            report["dataset"]["train_class_counts_used"] = used
        else:
            report["dataset"]["rf_train_class_counts_used"] = used

        print(f"[{time.time() - t0:6.0f}s] training {name} on {len(y):,} rows", flush=True)
        t1 = time.time()
        if name == "xgboost":
            model, weights = train_xgboost(X, y, params, args.seed, args.n_jobs)
        else:
            model, weights = train_random_forest(X, y, params, args.seed, args.n_jobs)
        train_seconds = time.time() - t1
        print(
            f"[{time.time() - t0:6.0f}s] {name} trained in {train_seconds:.0f}s; predicting test",
            flush=True,
        )

        t2 = time.time()
        pred = predict_labels(model, X_test, name)
        metrics = evaluate_all_views(y_test, pred)
        print(
            f"[{time.time() - t0:6.0f}s] {name}: acc {metrics['19_class']['accuracy']:.4f} "
            f"macroF1 {metrics['19_class']['f1_macro']:.4f} "
            f"attack-detect {metrics['binary_attack_vs_benign']['recall_attack_detection_rate']:.4f} "
            f"benign-FPR {metrics['binary_attack_vs_benign']['false_positive_rate_benign_flagged']:.5f}",
            flush=True,
        )

        entry = {
            "train_rows": int(len(y)),
            "train_seconds": round(train_seconds, 1),
            "predict_seconds": round(time.time() - t2, 1),
            "hyperparameters": params,
            "class_weights": weights,
            "metrics": metrics,
        }
        report["models"][name] = entry

        joblib.dump(model, out_dir / f"ciciomt2024_{name}.joblib")
        meta = {
            "model_name": name,
            "data_source": "CICIoMT2024 (real), official train/test split",
            "trained_at": datetime.now(UTC).isoformat(),
            "seed": args.seed,
            "labels": CLASS_NAMES,
            "feature_columns": FEATURE_COLUMNS,
            "feature_dtype": "float32",
            "train_rows_used": int(len(y)),
            "train_class_counts_used": used,
            "max_rows_per_class": cap,
            **{k: entry[k] for k in ("hyperparameters", "class_weights", "metrics")},
        }
        (out_dir / f"ciciomt2024_{name}.metadata.json").write_text(json.dumps(meta, indent=2))
        del X, y, model

    eval_dir: Path = args.report_dir
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / "ciciomt2024_results.json").write_text(json.dumps(report, indent=2))
    (eval_dir / "ciciomt2024_results.md").write_text(render_markdown(report))
    print(f"[{time.time() - t0:6.0f}s] wrote reports to {eval_dir}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, required=True, help="Folder containing train/ and test/.")
    parser.add_argument("--models-dir", type=Path, default=Path("../experiments/models"))
    parser.add_argument("--report-dir", type=Path, default=Path("../evaluation"))
    parser.add_argument("--models", nargs="+", default=["xgboost", "random_forest"],
                        choices=["xgboost", "random_forest"])
    parser.add_argument("--max-rows-per-class", type=int, default=DEFAULT_MAX_ROWS_PER_CLASS)
    parser.add_argument("--rf-max-rows-per-class", type=int, default=DEFAULT_RF_MAX_ROWS_PER_CLASS)
    parser.add_argument("--xgb-n-estimators", type=int, default=DEFAULT_XGB["n_estimators"])
    parser.add_argument("--rf-n-estimators", type=int, default=DEFAULT_RF["n_estimators"])
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
