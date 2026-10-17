"""Multi-seed, multi-classifier detector study on the real CICIoMT2024 test split.

`evaluation/ciciomt2024_results.md` reports one XGBoost and one Random Forest
trained once (seed 42) on up to 300,000 rows per class. A single training run
cannot show how much of a difference between two classifiers is just training
noise, so this script repeats the study:

* six classifiers (Decision Tree, Logistic Regression (stochastic gradient descent), Random Forest, Extra
  Trees, a small MLP, XGBoost);
* five training seeds each; a seed changes both the per-class row sample and the
  model's own randomness;
* a smaller per-class training cap (default 30,000 rows) so that 6 x 5 = 30
  trainings fit on a 2-CPU machine;
* every model is scored on the ENTIRE official test split (1,614,182 rows),
  which is never used for any choice.

Reported per classifier: mean and sample standard deviation over seeds of
19-class accuracy, 19-class macro-F1, attack-detection rate and benign
false-positive rate (binary view), plus training time.

The smaller cap means the XGBoost row here is NOT the same model as the one in
`ciciomt2024_results.md`; the report says so.

Usage (from `backend/`):
    python -m app.evaluation.run_detector_multiseed --data-dir /path/to/iomt
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from app.cybersecurity.ciciomt2024 import (
    CLASS_NAMES,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    cap_rows_per_class,
    load_split,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "evaluation"
_IDX = {c: i for i, c in enumerate(CLASS_NAMES)}
MODELS = ["decision_tree", "logistic_regression", "random_forest", "extra_trees", "mlp", "xgboost"]


def _signed_log1p(x):
    return np.sign(x) * np.log1p(np.abs(x))


def make_model(name: str, seed: int, n_jobs: int):
    if name == "decision_tree":
        return DecisionTreeClassifier(class_weight="balanced", random_state=seed)
    if name == "logistic_regression":
        return make_pipeline(
            FunctionTransformer(_signed_log1p),
            StandardScaler(),
            SGDClassifier(loss="log_loss", class_weight="balanced", max_iter=20, tol=None, random_state=seed),
        )
    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=n_jobs
        )
    if name == "extra_trees":
        return ExtraTreesClassifier(
            n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=n_jobs
        )
    if name == "mlp":
        return make_pipeline(
            FunctionTransformer(_signed_log1p),
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=(64,), max_iter=40, early_stopping=False, random_state=seed),
        )
    if name == "xgboost":
        return XGBClassifier(
            objective="multi:softprob",
            n_estimators=150,
            max_depth=8,
            learning_rate=0.2,
            tree_method="hist",
            max_bin=256,
            random_state=seed,
            n_jobs=n_jobs,
        )
    raise ValueError(name)


def predict_in_batches(model, X: np.ndarray, batch: int = 200_000) -> np.ndarray:
    out = np.empty(len(X), dtype=np.int32)
    for s in range(0, len(X), batch):
        out[s : s + batch] = model.predict(X[s : s + batch])
    return out


def scores(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    benign = _IDX["Benign"]
    attack = y_true != benign
    flagged = y_pred != benign
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", labels=list(range(len(CLASS_NAMES))))),
        "attack_detection": float((flagged & attack).sum() / attack.sum()),
        "benign_fpr": float((flagged & ~attack).sum() / (~attack).sum()),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--cap", type=int, default=30_000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--models", nargs="+", default=MODELS)
    ap.add_argument("--n-jobs", type=int, default=2)
    ap.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    args = ap.parse_args()
    t0 = time.time()

    def log(m: str) -> None:
        print(f"[{time.time() - t0:6.0f}s] {m}", flush=True)

    train_full = load_split(args.data_dir, "train")
    log(f"train loaded: {len(train_full):,} rows")
    test = load_split(args.data_dir, "test")
    X_test = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_test = np.array([_IDX[v] for v in test[LABEL_COLUMN]], dtype=np.int32)
    del test
    log(f"test loaded: {len(X_test):,} rows")

    runs: list[dict[str, Any]] = []
    out_json = args.output_dir / "detector_multiseed.json"
    for seed in args.seeds:
        sub = cap_rows_per_class(train_full, args.cap, seed=seed)
        X = sub[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
        y = np.array([_IDX[v] for v in sub[LABEL_COLUMN]], dtype=np.int32)
        del sub
        for name in args.models:
            t1 = time.time()
            model = make_model(name, seed, args.n_jobs)
            if name == "xgboost":
                counts = np.bincount(y, minlength=len(CLASS_NAMES)).astype(np.float64)
                w = (len(y) / (len(CLASS_NAMES) * counts))[y].astype(np.float32)
                model.fit(X, y, sample_weight=w)
            else:
                model.fit(X, y)
            train_s = time.time() - t1
            pred = predict_in_batches(model, X_test)
            row = {"model": name, "seed": seed, "train_rows": int(len(y)), "train_seconds": train_s}
            row.update(scores(y_test, pred))
            runs.append(row)
            log(
                f"seed {seed} {name}: acc {row['accuracy']:.4f} "
                f"macroF1 {row['macro_f1']:.4f} ({train_s:.0f}s)"
            )
            out_json.write_text(json.dumps({"runs": runs}, indent=2))
        del X, y

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "per_class_cap": args.cap,
        "seeds": args.seeds,
        "test_rows": int(len(y_test)),
        "runs": runs,
    }
    out_json.write_text(json.dumps(report, indent=2))
    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
