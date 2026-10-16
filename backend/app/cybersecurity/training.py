"""Baseline training pipeline for the detection engine.

Architecture spec Section 10: start with Random Forest and XGBoost -- the
standard, well-cited baselines for CICIoMT2024-style flow-feature data -- before
considering any deep-learning model. Class imbalance is handled with explicit
class weighting, documented here, not silently.

Data source: this script trains against whatever DataFrame it's given. By
default (no `--data-dir`) it uses the synthetic stand-in dataset in
`synthetic_data.py`, and every metric it prints or saves says "synthetic" --
see that module's docstring and datasets/LICENSE_NOTES.md for why.

The real CICIoMT2024 data is handled by its own, separate pipeline:
`ciciomt2024.py` (loader) and `train_ciciomt2024.py` (19-class training and
evaluation on the official train/test split). It is separate because the real
files have 45 flow features while this module's synthetic schema -- which the
runtime simulator's proxy features in `feature_extraction.py` are built to
match -- has 15, so the two models are not interchangeable. `load_real_dataset`
below therefore stays unimplemented on purpose.
"""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier

from app.cybersecurity.synthetic_data import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    generate_synthetic_dataset,
)


def load_real_dataset(data_dir: Path) -> pd.DataFrame:
    """Load and combine CICIoMT2024's real per-attack CSVs from `data_dir`.

    NOT IMPLEMENTED HERE, deliberately: the real loader lives in
    `app.cybersecurity.ciciomt2024` (`load_split`) and is trained/evaluated by
    `app.cybersecurity.train_ciciomt2024`. The real data has a different
    (45-column) feature schema from this module's synthetic one (15 columns),
    so loading it into `train_baselines` below would silently train a model the
    runtime detection service's feature extractor cannot feed.
    """
    raise NotImplementedError(
        "load_real_dataset is not implemented here: use app.cybersecurity.ciciomt2024.load_split "
        "and `python -m app.cybersecurity.train_ciciomt2024 --data-dir <folder with train/ and "
        "test/>` for the real CICIoMT2024 data (45-feature schema, separate pipeline). Run this "
        "script without --data-dir to train against the clearly-labeled synthetic stand-in."
    )


def compute_metrics(y_true, y_pred, labels: list[str]) -> dict[str, Any]:
    """Real, measured metrics -- never placeholders. Includes per-class false
    positive rate, which needs the confusion matrix rather than sklearn's
    built-in scorers."""
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    per_class_fpr: dict[str, float] = {}
    total = cm.sum()
    for i, label in enumerate(labels):
        false_positives = cm[:, i].sum() - cm[i, i]
        true_negatives = total - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        per_class_fpr[label] = (
            float(false_positives / (false_positives + true_negatives))
            if (false_positives + true_negatives) > 0
            else 0.0
        )

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_per_class": dict(
            zip(labels, f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0), strict=True)
        ),
        "false_positive_rate_per_class": per_class_fpr,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": labels,
    }


def train_baselines(df: pd.DataFrame, seed: int = 42) -> dict[str, Any]:
    """Train Random Forest and XGBoost baselines on `df`, report real metrics
    for both, and return everything needed to save artifacts + a metadata
    record (architecture spec Section 8: every model artifact is paired with a
    metadata JSON recording training data, hyperparameters, and metrics)."""

    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]
    labels = sorted(y.unique())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y
    )
    # Reset to a plain 0..n-1 index so every per-row array below (numpy
    # predictions, pd.Series predictions with a fresh default index) stays
    # positionally aligned with X_test/y_test for any caller that zips them
    # together row-by-row -- Phase 13's evaluation harness is exactly such a
    # caller (see app/evaluation/run_baseline_comparison.py), and the
    # original train_test_split index (sampled from df) is not otherwise
    # meaningful to preserve.
    X_test = X_test.reset_index(drop=True)
    y_test = y_test.reset_index(drop=True)

    class_weight_values = compute_class_weight(
        class_weight="balanced", classes=np.array(labels), y=y_train.to_numpy()
    )
    class_weight_map = dict(zip(labels, class_weight_values.tolist(), strict=True))
    sample_weight_train = y_train.map(class_weight_map)

    results: dict[str, Any] = {
        "labels": labels,
        "class_weights": class_weight_map,
        "models": {},
        # Phase 13 addition: the actual held-out split (not re-derived from a
        # second train_test_split call elsewhere, which -- even with the same
        # seed -- would be one more place to silently drift from what was
        # really trained on). Every per-row prediction below is positionally
        # aligned with these two.
        "test_data": {"X_test": X_test, "y_test": y_test},
    }

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    results["models"]["random_forest"] = {
        "estimator": rf,
        "hyperparameters": {"n_estimators": 200, "max_depth": None, "class_weight": "balanced"},
        "metrics": compute_metrics(y_test, rf_pred, labels),
        "predictions": pd.Series(rf_pred),
    }

    label_to_index = {label: i for i, label in enumerate(labels)}
    y_train_idx = y_train.map(label_to_index)
    y_test_idx = y_test.map(label_to_index)

    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softmax",
        num_class=len(labels),
        random_state=seed,
        eval_metric="mlogloss",
    )
    xgb.fit(X_train, y_train_idx, sample_weight=sample_weight_train)
    xgb_pred_idx = xgb.predict(X_test)
    xgb_pred = pd.Series(xgb_pred_idx).map({i: label for label, i in label_to_index.items()})
    results["models"]["xgboost"] = {
        "estimator": xgb,
        "hyperparameters": {"n_estimators": 200, "max_depth": 6, "learning_rate": 0.1},
        "metrics": compute_metrics(y_test_idx.map(lambda i: labels[i]), xgb_pred, labels),
        "predictions": xgb_pred,
    }

    return results


def save_artifacts(results: dict[str, Any], output_dir: Path, data_source: str, seed: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    trained_at = datetime.now(UTC).isoformat()

    for model_name, model_result in results["models"].items():
        model_path = output_dir / f"{model_name}.joblib"
        joblib.dump(model_result["estimator"], model_path)

        metadata = {
            "model_name": model_name,
            "data_source": data_source,
            "trained_at": trained_at,
            "seed": seed,
            "labels": results["labels"],
            "class_weights": results["class_weights"],
            "hyperparameters": model_result["hyperparameters"],
            "metrics": model_result["metrics"],
        }
        metadata_path = output_dir / f"{model_name}.metadata.json"
        metadata_path.write_text(json.dumps(metadata, indent=2))
        print(f"Saved {model_path} and {metadata_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory of real CICIoMT2024 CSVs. Omit to use the synthetic stand-in dataset.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/models"),
        help="Where to save trained model artifacts and metadata.",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.data_dir is not None:
        df = load_real_dataset(args.data_dir)
        data_source = f"CICIoMT2024 (real), loaded from {args.data_dir}"
    else:
        df = generate_synthetic_dataset(seed=args.seed)
        data_source = "SYNTHETIC stand-in dataset (not real CICIoMT2024 -- see datasets/LICENSE_NOTES.md)"
        print(
            "WARNING: training against synthetic stand-in data, not real "
            "CICIoMT2024. Metrics below are not a research result.\n",
            file=sys.stderr,
        )

    results = train_baselines(df, seed=args.seed)

    for model_name, model_result in results["models"].items():
        metrics = model_result["metrics"]
        print(f"\n=== {model_name} ({data_source}) ===")
        print(f"  accuracy:        {metrics['accuracy']:.4f}")
        print(f"  precision_macro: {metrics['precision_macro']:.4f}")
        print(f"  recall_macro:    {metrics['recall_macro']:.4f}")
        print(f"  f1_macro:        {metrics['f1_macro']:.4f}")

    save_artifacts(results, args.output, data_source, args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
