"""Unsupervised anomaly detection.

Necessary rather than decorative: the supervised detector can only recognise
attack families present in its training labels, and a hospital will meet
attacks that were not. The anomaly detector is trained on benign traffic
only and flags deviation, so it provides coverage for novel behaviour at the
cost of a higher false-positive rate.

That trade-off is the point, and the ablation study measures it: the
``unseen_attack`` split protocol exists to test exactly this claim rather
than assert it.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.app.domain.enums import AttackType, DetectorKind
from backend.app.domain.models import DetectionResult
from cybersecurity.detectors.base import Detector, DetectorMetadata
from cybersecurity.detectors.supervised import windows_to_matrix
from cybersecurity.features.extractor import FeatureWindow
from cybersecurity.schema import LOG_SCALE_FEATURES


class AnomalyDetector(Detector):
    """Isolation-Forest novelty detector fitted on benign traffic only."""

    def __init__(
        self,
        contamination: float = 0.05,
        seed: int = 20260101,
        score_threshold: float | None = None,
        name: str = "isolation_forest",
    ) -> None:
        super().__init__(
            DetectorMetadata(
                name=name,
                kind=DetectorKind.ANOMALY_DETECTOR,
                model_version="untrained",
                hyperparameters={"contamination": contamination, "seed": seed},
            )
        )
        self.contamination = contamination
        self.seed = seed
        self.score_threshold = score_threshold
        self._pipeline: Pipeline | None = None
        self._feature_order: list[str] = []
        self._train_scores: np.ndarray | None = None

    @property
    def is_fitted(self) -> bool:
        return self._pipeline is not None

    def fit(self, windows: list[FeatureWindow], benign_only: bool = True) -> dict[str, object]:
        """Fit on benign windows.

        ``benign_only=True`` is the honest configuration: a novelty detector
        trained on contaminated data learns to treat attacks as normal.
        """
        training = [w for w in windows if w.y_binary == 0] if benign_only else list(windows)
        if len(training) < 20:
            raise ValueError(
                f"only {len(training)} benign windows available; too few to "
                "characterise normal behaviour"
            )
        X, _, names = windows_to_matrix(training)
        observed = ~np.all(np.isnan(X), axis=0)
        X = X[:, observed]
        names = [n for n, k in zip(names, observed, strict=True) if k]
        self._feature_order = names

        self._pipeline = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median")),
                ("scale", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=200,
                        contamination=self.contamination,
                        random_state=self.seed,
                        n_jobs=1,
                    ),
                ),
            ]
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._pipeline.fit(X)
            self._train_scores = -self._pipeline.named_steps["model"].score_samples(
                self._pipeline.named_steps["scale"].transform(
                    self._pipeline.named_steps["impute"].transform(X)
                )
            )

        if self.score_threshold is None and self._train_scores is not None:
            # Threshold at the (1 - contamination) quantile of benign scores,
            # so the nominal benign false-positive rate equals contamination.
            self.score_threshold = float(np.quantile(self._train_scores, 1.0 - self.contamination))

        self.metadata.model_version = f"iforest-s{self.seed}-c{self.contamination}-n{len(training)}"
        self.metadata.feature_order = tuple(names)
        self.metadata.training_rows = len(training)
        return {
            "n_benign_train": len(training),
            "n_features": len(names),
            "score_threshold": self.score_threshold,
            "benign_score_mean": float(np.mean(self._train_scores)),
        }

    def _vector(self, window: FeatureWindow) -> np.ndarray:
        v = np.full((1, len(self._feature_order)), np.nan)
        for j, name in enumerate(self._feature_order):
            if name in window.features:
                val = window.features[name]
                if name in LOG_SCALE_FEATURES:
                    val = float(np.log1p(max(0.0, val)))
                v[0, j] = val
        return v

    def anomaly_score(self, window: FeatureWindow) -> float:
        if self._pipeline is None:
            raise RuntimeError("detector is not fitted")
        v = self._vector(window)
        imp = self._pipeline.named_steps["impute"].transform(v)
        sc = self._pipeline.named_steps["scale"].transform(imp)
        return float(-self._pipeline.named_steps["model"].score_samples(sc)[0])

    def predict_window(self, window: FeatureWindow) -> DetectionResult:
        score = self.anomaly_score(window)
        threshold = self.score_threshold if self.score_threshold is not None else 0.5
        is_attack = score >= threshold
        # Confidence from how far past the threshold the score lies, scaled
        # by the benign score spread. Deliberately capped below certainty: an
        # anomaly detector knows that something is unusual, never what it is.
        spread = float(np.std(self._train_scores)) if self._train_scores is not None else 0.1
        margin = (score - threshold) / max(spread, 1e-6)
        confidence = min(0.85, 0.5 + 0.15 * margin) if is_attack else min(0.9, 0.5 - 0.15 * margin)
        return self._result(
            window,
            is_attack=is_attack,
            # An anomaly detector cannot name the attack. Claiming otherwise
            # would be fabricating an inference the model cannot support.
            attack_type=AttackType.UNKNOWN if is_attack else AttackType.NONE,
            confidence=max(0.0, min(1.0, confidence)),
            anomaly_score=round(score, 6),
            class_scores={"anomaly_score": round(score, 6), "threshold": round(threshold, 6)},
            contributing=self._deviating_features(window),
            notes=f"isolation forest score={score:.4f} threshold={threshold:.4f}",
        )

    def _deviating_features(self, window: FeatureWindow, k: int = 5) -> dict[str, float]:
        """Features furthest from the benign mean, in standard deviations.

        Gives the investigation agent something concrete to cite, since the
        model itself offers no per-feature attribution.
        """
        if self._pipeline is None:
            return {}
        scaler: StandardScaler = self._pipeline.named_steps["scale"]
        v = self._pipeline.named_steps["impute"].transform(self._vector(window))
        z = scaler.transform(v)[0]
        order = np.argsort(np.abs(z))[::-1][:k]
        return {
            self._feature_order[j]: round(float(z[j]), 4)
            for j in order
            if self._feature_order[j] in window.features
        }


@dataclass
class EnsembleDetector(Detector):
    """Combines a supervised detector with an anomaly detector.

    Union logic: either component flagging raises an incident. The
    supervised model carries attack attribution; the anomaly model
    contributes novel-behaviour coverage. Confidence is taken from whichever
    component fired, and attribution is only claimed when the supervised
    model fired, so unknown-but-anomalous traffic is reported as UNKNOWN
    rather than mislabelled.
    """

    def __init__(self, supervised: Detector, anomaly: AnomalyDetector) -> None:
        super().__init__(
            DetectorMetadata(
                name="ensemble",
                kind=DetectorKind.ENSEMBLE,
                model_version=f"{supervised.metadata.model_version}+{anomaly.metadata.model_version}",
            )
        )
        self.supervised = supervised
        self.anomaly = anomaly

    def predict_window(self, window: FeatureWindow) -> DetectionResult:
        sup = self.supervised.predict_window(window)
        ano = self.anomaly.predict_window(window)
        if sup.is_attack:
            return sup.model_copy(
                update={
                    "detector_name": "ensemble",
                    "detector_kind": DetectorKind.ENSEMBLE,
                    "anomaly_score": ano.anomaly_score,
                    "notes": f"supervised fired; {sup.notes}; anomaly {ano.notes}",
                }
            )
        if ano.is_attack:
            return ano.model_copy(
                update={
                    "detector_name": "ensemble",
                    "detector_kind": DetectorKind.ENSEMBLE,
                    "notes": (
                        "anomaly-only detection: behaviour deviates from the "
                        f"benign baseline but matches no known family; {ano.notes}"
                    ),
                }
            )
        return sup.model_copy(
            update={
                "detector_name": "ensemble",
                "detector_kind": DetectorKind.ENSEMBLE,
                "anomaly_score": ano.anomaly_score,
                "notes": "neither component fired",
            }
        )


__all__ = ["AnomalyDetector", "EnsembleDetector"]
