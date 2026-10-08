"""Supervised detection models.

Provides a baseline ladder rather than one model, because a single reported
model with no weaker comparison tells a reader nothing about whether the
complexity was warranted:

    rules  ->  logistic regression  ->  random forest  ->  gradient boosting

Preprocessing is fitted on training data only and persisted with the model,
so inference cannot leak test statistics. The trainer refuses to fit if any
forbidden column is present, and records the univariate AUC of every feature
so a degenerate task cannot be reported as a success.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.app.domain.enums import AttackType, DetectorKind
from backend.app.domain.models import DetectionResult
from cybersecurity.detectors.base import Detector, DetectorMetadata
from cybersecurity.features.extractor import FeatureWindow
from cybersecurity.schema import FEATURE_NAMES, LOG_SCALE_FEATURES, assert_no_leakage

ModelName = Literal["logistic_regression", "random_forest", "gradient_boosting"]


def build_estimator(name: ModelName, seed: int = 20260101, **kwargs: Any) -> Any:
    """Construct an estimator with defensible, documented defaults.

    ``class_weight="balanced"`` is used wherever supported because the
    natural attack prevalence is a small minority; without it a model
    maximises accuracy by predicting "benign" everywhere.
    """
    if name == "logistic_regression":
        params = {
            "max_iter": 2000,
            "class_weight": "balanced",
            "random_state": seed,
            "C": 1.0,
        }
        params.update(kwargs)
        return LogisticRegression(**params)
    if name == "random_forest":
        params = {
            "n_estimators": 200,
            "min_samples_leaf": 2,
            "class_weight": "balanced_subsample",
            "random_state": seed,
            # Single-threaded by default: n_jobs=-1 spawns a worker per core
            # per fit, which exhausted memory on a 2-core CI sandbox fitting
            # many models in one process. Callers that want parallelism pass
            # n_jobs explicitly.
            "n_jobs": 1,
        }
        params.update(kwargs)
        return RandomForestClassifier(**params)
    if name == "gradient_boosting":
        # HistGradientBoosting rather than XGBoost: comparable performance,
        # no extra dependency, native NaN handling, and in sklearn so the
        # reproducibility story is one library version.
        params = {
            "max_iter": 400,
            "learning_rate": 0.06,
            "max_leaf_nodes": 31,
            "l2_regularization": 1.0,
            "random_state": seed,
            "early_stopping": True,
            "validation_fraction": 0.15,
        }
        params.update(kwargs)
        return HistGradientBoostingClassifier(**params)
    raise ValueError(f"unknown model {name!r}")


@dataclass
class TrainingReport:
    """Everything needed to reproduce and audit a fit."""

    model_name: str
    seed: int
    n_train: int
    n_features: int
    feature_order: tuple[str, ...]
    class_balance: dict[str, int]
    univariate_auc: dict[str, float] = field(default_factory=dict)
    unavailable_features: tuple[str, ...] = ()
    fitted_at: datetime | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def max_univariate_auc(self) -> tuple[str, float] | None:
        if not self.univariate_auc:
            return None
        k = max(self.univariate_auc, key=lambda n: self.univariate_auc[n])
        return k, self.univariate_auc[k]


def windows_to_matrix(
    windows: list[FeatureWindow],
    feature_order: tuple[str, ...] = FEATURE_NAMES,
    log_scale: bool = True,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Build (X, y, feature_names) from feature windows.

    Features absent from a window become NaN rather than 0.0, because 0.0 is
    a meaningful value for most of these features and imputing it would be a
    silent lie. Tree models handle NaN natively; the linear pipeline imputes
    explicitly.
    """
    assert_no_leakage(list(feature_order))
    present = [name for name in feature_order if any(name in w.features for w in windows)]
    X = np.full((len(windows), len(present)), np.nan, dtype=float)
    for i, w in enumerate(windows):
        for j, name in enumerate(present):
            if name in w.features:
                X[i, j] = w.features[name]
    if log_scale:
        for j, name in enumerate(present):
            if name in LOG_SCALE_FEATURES:
                col = X[:, j]
                X[:, j] = np.where(np.isnan(col), np.nan, np.log1p(np.clip(col, 0, None)))
    y = np.array([w.y_binary for w in windows], dtype=int)
    return X, y, present


def univariate_aucs(X: np.ndarray, y: np.ndarray, names: list[str]) -> dict[str, float]:
    """Orientation-independent single-feature AUC, for degeneracy reporting."""
    out: dict[str, float] = {}
    if len(set(y.tolist())) < 2:
        return out
    for j, name in enumerate(names):
        col = X[:, j]
        mask = ~np.isnan(col)
        if mask.sum() < 10 or len(set(y[mask].tolist())) < 2:
            continue
        vals = col[mask]
        if vals.min() == vals.max():
            continue
        auc = roc_auc_score(y[mask], vals)
        out[name] = round(float(max(auc, 1.0 - auc)), 4)
    return out


class SupervisedDetector(Detector):
    """Binary attack detector with an attack-type head.

    Two-stage by design, mirroring how the comparison literature reports
    CICIoMT2024: a benign-vs-attack gate, then attack-family attribution
    only on flagged traffic. Keeping them separate means a weak
    multi-class head cannot degrade the binary decision the response loop
    depends on.
    """

    def __init__(
        self,
        model_name: ModelName = "gradient_boosting",
        seed: int = 20260101,
        decision_threshold: float = 0.5,
        name: str | None = None,
    ) -> None:
        super().__init__(
            DetectorMetadata(
                name=name or f"supervised_{model_name}",
                kind=DetectorKind.SUPERVISED_CLASSIFIER,
                model_version="untrained",
                hyperparameters={"model": model_name, "seed": seed},
            )
        )
        self.model_name = model_name
        self.seed = seed
        self.decision_threshold = decision_threshold
        self._pipeline: Any = None
        self._type_pipeline: Any = None
        self._type_classes: list[str] = []
        self._type_fill: np.ndarray | None = None
        self._feature_order: list[str] = []
        self.report: TrainingReport | None = None

    @property
    def is_fitted(self) -> bool:
        return self._pipeline is not None

    # -- training ----------------------------------------------------------
    def fit(
        self,
        windows: list[FeatureWindow],
        fit_attack_type_head: bool = True,
    ) -> TrainingReport:
        if not windows:
            raise ValueError("no training windows supplied")
        X, y, names = windows_to_matrix(windows)
        if len(set(y.tolist())) < 2:
            raise ValueError(
                "training data contains a single class; a detector cannot be "
                "fitted. Use a scenario containing both benign and attack traffic."
            )

        # Drop columns with no observed value in training. Keeping them makes
        # the imputer skip them, which silently shifts downstream column
        # indices, and the model would in any case learn nothing from them.
        observed = ~np.all(np.isnan(X), axis=0)
        X = X[:, observed]
        names = [n for n, keep in zip(names, observed, strict=True) if keep]
        self._feature_order = names

        needs_imputation = self.model_name == "logistic_regression"
        steps = []
        if needs_imputation:
            steps.append(("impute", SimpleImputer(strategy="median")))
            steps.append(("scale", StandardScaler()))
        steps.append(("model", build_estimator(self.model_name, self.seed)))
        self._pipeline = Pipeline(steps)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._pipeline.fit(X, y)

        aucs = univariate_aucs(X, y, names)
        msgs: list[str] = []
        if aucs:
            top_name, top_auc = max(aucs.items(), key=lambda kv: kv[1])
            if top_auc >= 0.99:
                msgs.append(
                    f"DEGENERACY WARNING: feature {top_name!r} alone achieves "
                    f"AUC {top_auc:.3f}. The task may be trivially separable and "
                    "reported metrics may be meaningless. See "
                    "docs/detection-validity.md."
                )

        missing = tuple(n for n in FEATURE_NAMES if n not in names)
        self.report = TrainingReport(
            model_name=self.model_name,
            seed=self.seed,
            n_train=len(windows),
            n_features=len(names),
            feature_order=tuple(names),
            class_balance={
                "benign": int((y == 0).sum()),
                "attack": int((y == 1).sum()),
            },
            univariate_auc=aucs,
            unavailable_features=missing,
            fitted_at=datetime.now(UTC),
            warnings=msgs,
        )

        self.metadata.model_version = (
            f"{self.model_name}-s{self.seed}-n{len(windows)}-f{len(names)}"
        )
        self.metadata.trained_at = self.report.fitted_at
        self.metadata.feature_order = tuple(names)
        self.metadata.training_rows = len(windows)
        self.metadata.unavailable_features = missing
        self.metadata.univariate_auc = aucs

        if fit_attack_type_head:
            self._fit_type_head(X, windows)
        return self.report

    def _fit_type_head(self, X: np.ndarray, windows: list[FeatureWindow]) -> None:
        """Fit attack-family attribution on attack windows only.

        ``X`` is already restricted to columns observed in the full training
        set, but a column can still be entirely absent among the *attack*
        rows alone. Those columns are imputed with the overall training
        median rather than left for SimpleImputer to silently drop, which
        would shift the column indices this pipeline expects at inference.
        """
        idx = [i for i, w in enumerate(windows) if w.y_binary == 1]
        labels = [windows[i].y_attack_type for i in idx]
        if len(set(labels)) < 2:
            self._type_pipeline = None
            return

        Xa = X[idx].copy()
        # Column medians over ALL training rows, so a feature unobserved among
        # attack rows still gets a defensible fill value.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            overall_median = np.nanmedian(X, axis=0)
        overall_median = np.where(np.isnan(overall_median), 0.0, overall_median)
        empty_cols = np.all(np.isnan(Xa), axis=0)
        if empty_cols.any():
            Xa[:, empty_cols] = overall_median[empty_cols]
        self._type_fill = overall_median

        pipe = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median")),
                ("model", build_estimator("random_forest", self.seed)),
            ]
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pipe.fit(Xa, labels)
        self._type_pipeline = pipe
        self._type_classes = list(pipe.named_steps["model"].classes_)

    # -- inference ---------------------------------------------------------
    def _vector(self, window: FeatureWindow) -> np.ndarray:
        v = np.full((1, len(self._feature_order)), np.nan)
        for j, name in enumerate(self._feature_order):
            if name in window.features:
                val = window.features[name]
                if name in LOG_SCALE_FEATURES:
                    val = float(np.log1p(max(0.0, val)))
                v[0, j] = val
        return v

    def predict_window(self, window: FeatureWindow) -> DetectionResult:
        if not self.is_fitted:
            raise RuntimeError("detector is not fitted; call fit() first")
        v = self._vector(window)
        proba = float(self._pipeline.predict_proba(v)[0, 1])
        is_attack = proba >= self.decision_threshold

        attack_type = AttackType.UNKNOWN
        class_scores: dict[str, float] = {"attack_probability": round(proba, 6)}
        if is_attack and self._type_pipeline is not None:
            vt = v.copy()
            fill = getattr(self, "_type_fill", None)
            if fill is not None:
                nan_mask = np.isnan(vt[0])
                vt[0, nan_mask] = fill[nan_mask]
            probs = self._type_pipeline.predict_proba(vt)[0]
            best = int(np.argmax(probs))
            raw = self._type_classes[best]
            try:
                attack_type = AttackType(raw)
            except ValueError:
                attack_type = AttackType.UNKNOWN
            class_scores.update(
                {str(c): round(float(p), 6) for c, p in zip(self._type_classes, probs, strict=True)}
            )
        elif not is_attack:
            attack_type = AttackType.NONE

        return self._result(
            window,
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=proba if is_attack else 1.0 - proba,
            anomaly_score=None,
            class_scores=class_scores,
            contributing=self._top_contributions(window),
            notes=f"{self.model_name} p(attack)={proba:.4f}",
        )

    def _top_contributions(self, window: FeatureWindow, k: int = 5) -> dict[str, float]:
        """Report the model's most important features, with their values.

        Global importance rather than per-sample attribution: honest about
        what it is, and the investigation agent cites the observed values,
        not the importance weights.
        """
        importances = self._raw_importances()
        if importances is None or len(importances) != len(self._feature_order):
            # No native importances: report the observed values of the
            # features present, rather than inventing a ranking.
            return {
                n: round(window.features[n], 6)
                for n in self._feature_order[:k]
                if n in window.features
            }
        order = np.argsort(importances)[::-1][:k]
        return {
            self._feature_order[j]: round(window.features.get(self._feature_order[j], 0.0), 6)
            for j in order
            if self._feature_order[j] in window.features
        }

    def _raw_importances(self) -> np.ndarray | None:
        """Model-native importances, or None when the model exposes none.

        HistGradientBoostingClassifier deliberately exposes no
        ``feature_importances_``; permutation importance is the supported
        route. We report that honestly rather than fabricating a ranking.
        """
        model = self._pipeline.named_steps.get("model")
        imp = getattr(model, "feature_importances_", None)
        if imp is not None:
            return np.asarray(imp, dtype=float)
        coef = getattr(model, "coef_", None)
        if coef is not None:
            return np.abs(np.asarray(coef, dtype=float)[0])
        return None

    def feature_importances(self) -> dict[str, float]:
        """Global feature importance, where the model provides it."""
        imp = self._raw_importances()
        if imp is None or len(imp) != len(self._feature_order):
            return {}
        return {
            n: round(float(v), 6)
            for n, v in sorted(
                zip(self._feature_order, imp, strict=True),
                key=lambda kv: kv[1],
                reverse=True,
            )
        }

    def permutation_importances(
        self,
        windows: list[FeatureWindow],
        n_repeats: int = 5,
        scoring: str = "average_precision",
    ) -> dict[str, float]:
        """Permutation importance on held-out data.

        The only importance measure available for models without native
        importances, and the more trustworthy measure in general: it reports
        the drop in held-out score when a feature is shuffled, rather than
        the model's internal split statistics.
        """
        from sklearn.inspection import permutation_importance

        if not self.is_fitted:
            raise RuntimeError("detector is not fitted")
        X = np.vstack([self._vector(w) for w in windows])
        y = np.array([w.y_binary for w in windows], dtype=int)
        if len(set(y.tolist())) < 2:
            return {}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = permutation_importance(
                self._pipeline,
                X,
                y,
                n_repeats=n_repeats,
                random_state=self.seed,
                scoring=scoring,
            )
        return {
            n: round(float(v), 6)
            for n, v in sorted(
                zip(self._feature_order, r.importances_mean, strict=True),
                key=lambda kv: kv[1],
                reverse=True,
            )
        }

    # -- persistence -------------------------------------------------------
    def save(self, path: str | Path) -> Path:
        import joblib

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "pipeline": self._pipeline,
                "type_pipeline": self._type_pipeline,
                "type_classes": self._type_classes,
                "type_fill": self._type_fill,
                "feature_order": self._feature_order,
                "metadata": self.metadata,
                "report": self.report,
                "model_name": self.model_name,
                "seed": self.seed,
                "decision_threshold": self.decision_threshold,
            },
            p,
        )
        return p

    @classmethod
    def load(cls, path: str | Path) -> SupervisedDetector:
        import joblib

        blob = joblib.load(Path(path))
        det = cls(
            model_name=blob["model_name"],
            seed=blob["seed"],
            decision_threshold=blob["decision_threshold"],
        )
        det._pipeline = blob["pipeline"]
        det._type_pipeline = blob["type_pipeline"]
        det._type_classes = blob["type_classes"]
        det._type_fill = blob.get("type_fill")
        det._feature_order = blob["feature_order"]
        det.metadata = blob["metadata"]
        det.report = blob["report"]
        return det


__all__ = [
    "ModelName",
    "SupervisedDetector",
    "TrainingReport",
    "build_estimator",
    "univariate_aucs",
    "windows_to_matrix",
]
