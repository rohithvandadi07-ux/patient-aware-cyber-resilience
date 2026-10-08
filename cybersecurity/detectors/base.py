"""Detector interface and shared plumbing."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    DetectorKind,
    Severity,
)
from backend.app.domain.models import DetectionResult
from cybersecurity.features.extractor import FeatureWindow

#: Mapping from attack class to a default severity. Severity is a property of
#: the attack class, not of the asset: asset-dependent consequences belong to
#: the clinical-risk engine, deliberately kept separate so that the
#: cyber/clinical separation stays clean and independently ablatable.
ATTACK_SEVERITY: dict[AttackType, Severity] = {
    AttackType.NONE: Severity.INFO,
    AttackType.RECONNAISSANCE: Severity.LOW,
    AttackType.PORT_SCAN: Severity.LOW,
    AttackType.ARP_SPOOFING: Severity.MEDIUM,
    AttackType.DOS: Severity.MEDIUM,
    AttackType.DDOS: Severity.HIGH,
    AttackType.MITM: Severity.HIGH,
    AttackType.UNAUTHORIZED_ACCESS: Severity.HIGH,
    AttackType.CREDENTIAL_BRUTE_FORCE: Severity.MEDIUM,
    AttackType.SPOOFED_TELEMETRY: Severity.HIGH,
    AttackType.MALICIOUS_COMMAND: Severity.CRITICAL,
    AttackType.FIRMWARE_TAMPER: Severity.CRITICAL,
    AttackType.RANSOMWARE_BEHAVIOUR: Severity.CRITICAL,
    AttackType.UNKNOWN: Severity.MEDIUM,
}


@dataclass
class DetectorMetadata:
    """Versioning information carried into every result and provenance record."""

    name: str
    kind: DetectorKind
    model_version: str = "unversioned"
    trained_at: datetime | None = None
    feature_order: tuple[str, ...] = ()
    training_corpus: str = ""
    training_rows: int = 0
    unavailable_features: tuple[str, ...] = ()
    hyperparameters: dict[str, object] = field(default_factory=dict)
    # Univariate AUC per feature on the training set. Published alongside
    # results so a reader can verify no single feature dominates.
    univariate_auc: dict[str, float] = field(default_factory=dict)

    def max_univariate_auc(self) -> tuple[str, float] | None:
        if not self.univariate_auc:
            return None
        name = max(self.univariate_auc, key=lambda k: self.univariate_auc[k])
        return name, self.univariate_auc[name]


class Detector(ABC):
    """Base class for all detectors."""

    def __init__(self, metadata: DetectorMetadata) -> None:
        self.metadata = metadata

    @abstractmethod
    def predict_window(self, window: FeatureWindow) -> DetectionResult:
        """Classify a single feature window."""

    def predict(self, windows: list[FeatureWindow]) -> list[DetectionResult]:
        return [self.predict_window(w) for w in windows]

    # -- helpers -----------------------------------------------------------
    def _result(
        self,
        window: FeatureWindow,
        is_attack: bool,
        attack_type: AttackType,
        confidence: float,
        anomaly_score: float | None = None,
        class_scores: dict[str, float] | None = None,
        contributing: dict[str, float] | None = None,
        notes: str = "",
    ) -> DetectionResult:
        return DetectionResult(
            detector_name=self.metadata.name,
            detector_kind=self.metadata.kind,
            model_version=self.metadata.model_version,
            timestamp=window.window_end,
            device_id=window.device_id,
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=max(0.0, min(1.0, confidence)),
            anomaly_score=anomaly_score,
            severity=ATTACK_SEVERITY.get(attack_type, Severity.MEDIUM)
            if is_attack
            else Severity.INFO,
            class_scores=class_scores or {},
            contributing_features=contributing or {},
            window_start=window.window_start,
            window_end=window.window_end,
            evidence_event_ids=list(window.event_ids),
            assertion_class=AssertionClass.INFERENCE,
            notes=notes,
        )


__all__ = ["ATTACK_SEVERITY", "Detector", "DetectorMetadata"]
