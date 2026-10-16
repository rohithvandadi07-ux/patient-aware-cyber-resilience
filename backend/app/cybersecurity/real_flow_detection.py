"""Runtime scoring of REAL CICIoMT2024 flow-feature vectors.

Why a second detection service
------------------------------
`detection_service.DetectionService` scores a `FeatureWindow` built from the
simulator's event stream through `extract_features`, a 15-feature *proxy*
schema (see `synthetic_data.py`). Those 15 features are not the 45 real
CICFlowMeter-style features the real CICIoMT2024 models were trained on, and
nothing in this repository can derive the 45 from simulator events (flag
counts, IAT, covariance, ... need real packet captures). Pretending otherwise
would be fabricating features, so the two pipelines stay separate:

* `DetectionService` (unchanged): simulator events -> 15 proxy features ->
  proxy-trained model. Used by `/detections/run-scenario`.
* `RealFlowDetectionService` (this module): a flow sensor that already emits
  the 45 real features (the shape of the dataset's own CSVs) -> the real
  19-class model trained by `train_ciciomt2024.py`. Used by
  `/detections/score-flows`.

Both emit the same `DetectionEvent`, so everything downstream (incident
creation, agents, risk and policy engines, response, recovery, provenance) is
identical and unaware of which detector produced the evidence.

Label mapping
-------------
The detector predicts one of 19 classes; `DetectionEvent.attack_type` is the
coarser `AttackCategory`. The mapping goes through the dataset's 6 families,
the same one the real-data safety comparison uses:
ARP_Spoofing -> spoofing, MQTT-* -> mqtt_based, Recon-* -> reconnaissance,
TCP_IP-DoS-* -> dos, TCP_IP-DDoS-* -> ddos, Benign -> no event. The fine
19-class label is kept on the per-flow result so it is not lost.

The confidence threshold and severity rule are the same ones as
`DetectionService` (0.6; >=0.85 -> CRITICAL, else HIGH). The detector's
softmax confidence is NOT calibrated (see `evaluation/confidence_gating.md`).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import joblib
import numpy as np

from app.cybersecurity.ciciomt2024 import BENIGN, CLASS_NAMES, FEATURE_COLUMNS, family_of
from app.cybersecurity.detection_service import (
    _HIGH_CONFIDENCE_CUTOFF,
    DEFAULT_CONFIDENCE_THRESHOLD,
)
from app.schemas.detection import DetectionEvent
from app.schemas.enums import AttackCategory, ImpactLevel

FAMILY_TO_ATTACK_CATEGORY: dict[str, AttackCategory] = {
    "ARP_Spoofing": AttackCategory.SPOOFING,
    "MQTT": AttackCategory.MQTT_BASED,
    "Recon": AttackCategory.RECONNAISSANCE,
    "DoS": AttackCategory.DOS,
    "DDoS": AttackCategory.DDOS,
}


class InvalidFlowError(ValueError):
    """A flow record is missing features or holds a non-finite value."""


@dataclass(frozen=True)
class FlowResult:
    """The detector's verdict on one flow."""

    flow_index: int
    predicted_class: str  # one of the 19 CICIoMT2024 classes
    family: str  # one of the 6 families
    confidence: float
    detection: DetectionEvent | None  # None when benign or below threshold


def flows_to_matrix(flows: Sequence[Mapping[str, float]]) -> np.ndarray:
    """Validate flow records and stack them into a (n, 45) float32 matrix in
    the model's column order. Raises `InvalidFlowError` rather than guessing a
    value for a missing feature (no silent zero-fill: a zero is a real
    feature value, not 'unknown')."""
    if not flows:
        raise InvalidFlowError("at least one flow is required")
    matrix = np.empty((len(flows), len(FEATURE_COLUMNS)), dtype=np.float32)
    for i, flow in enumerate(flows):
        missing = [c for c in FEATURE_COLUMNS if c not in flow]
        if missing:
            raise InvalidFlowError(f"flow {i} is missing {len(missing)} feature(s): {missing[:5]}")
        for j, column in enumerate(FEATURE_COLUMNS):
            value = float(flow[column])
            if not math.isfinite(value):
                raise InvalidFlowError(f"flow {i} has a non-finite value for {column!r}")
            matrix[i, j] = value
    return matrix


class RealFlowDetectionService:
    """Wraps one loaded real-data 19-class model. Stateless across calls."""

    def __init__(
        self,
        estimator: object,
        labels: list[str],
        model_name: str,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        if not hasattr(estimator, "predict_proba"):
            raise TypeError(
                f"estimator for {model_name!r} has no predict_proba; confidence must be a measured "
                "probability, not a fabricated constant"
            )
        if sorted(labels) != sorted(CLASS_NAMES):
            raise ValueError("model labels are not the 19 CICIoMT2024 classes; refusing to load")
        self._estimator = estimator
        self._labels = labels
        self._model_name = model_name
        self._threshold = confidence_threshold

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def confidence_threshold(self) -> float:
        return self._threshold

    @classmethod
    def from_artifact(
        cls, model_path: Path, confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    ) -> RealFlowDetectionService:
        """Load a `ciciomt2024_<model>.joblib` plus its `.metadata.json`
        (both written by `train_ciciomt2024.py`)."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(
                f"Real-data model not found at {model_path}. Train one first:\n"
                "    python -m app.cybersecurity.train_ciciomt2024 --data-dir <iomt folder>"
            )
        metadata_path = model_path.with_suffix(".metadata.json")
        if not metadata_path.exists():
            raise FileNotFoundError(f"No paired metadata file at {metadata_path}")
        metadata = json.loads(metadata_path.read_text())
        if list(metadata.get("feature_columns", [])) != FEATURE_COLUMNS:
            raise ValueError(
                f"{metadata_path.name}: feature columns differ from the loader's 45; refusing to score"
            )
        return cls(
            estimator=joblib.load(model_path),
            labels=list(metadata["labels"]),
            model_name=metadata["model_name"],
            confidence_threshold=confidence_threshold,
        )

    def _decode(self, class_value: object) -> str:
        # RandomForest was fit on string labels; XGBoost on integer-encoded
        # labels in CLASS_NAMES order (train_ciciomt2024.predict_labels).
        if isinstance(class_value, str):
            return class_value
        return CLASS_NAMES[int(class_value)]  # type: ignore[call-overload]

    def predict(self, matrix: np.ndarray) -> tuple[list[str], np.ndarray]:
        """Batch (label, confidence) for a (n, 45) matrix."""
        proba = self._estimator.predict_proba(matrix)  # type: ignore[attr-defined]
        best = proba.argmax(axis=1)
        classes = list(self._estimator.classes_)  # type: ignore[attr-defined]
        labels = [self._decode(classes[i]) for i in best]
        return labels, proba[np.arange(len(best)), best].astype(float)

    def score_flows(
        self,
        device_id: str,
        flows: Sequence[Mapping[str, float]],
        timestamp: datetime | None = None,
    ) -> list[FlowResult]:
        """Score a batch of flows observed on one device."""
        matrix = flows_to_matrix(flows)
        labels, confidences = self.predict(matrix)
        when = timestamp or datetime.now(UTC)
        batch_ref = uuid4().hex[:8]

        results: list[FlowResult] = []
        for i, (label, confidence) in enumerate(zip(labels, confidences, strict=True)):
            family = family_of(label)
            detection = None
            if label != BENIGN and confidence >= self._threshold:
                detection = DetectionEvent(
                    device_id=device_id,
                    attack_type=FAMILY_TO_ATTACK_CATEGORY[family],
                    confidence=float(confidence),
                    severity_hint=(
                        ImpactLevel.CRITICAL if confidence >= _HIGH_CONFIDENCE_CUTOFF else ImpactLevel.HIGH
                    ),
                    timestamp=when,
                    evidence_ref=(
                        f"flows[{device_id}][batch={batch_ref}][index={i}]"
                        f"[class={label}][model={self._model_name}]"
                    ),
                )
            results.append(
                FlowResult(
                    flow_index=i,
                    predicted_class=label,
                    family=family,
                    confidence=float(confidence),
                    detection=detection,
                )
            )
        return results
