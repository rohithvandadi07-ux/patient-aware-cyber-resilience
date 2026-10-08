"""Cyber-risk scoring.

Answers "how dangerous is this attack, as an attack?" and nothing else.

The deliberate design constraint is that this term is **asset-agnostic**:
device importance and patient dependency belong to clinical risk. Mixing
them here would make the two terms correlated, and the ablation study
"without clinical criticality" would then be measuring a confounded
quantity rather than a clean removal.
"""

from __future__ import annotations

from backend.app.domain.enums import AssertionClass, AttackType
from backend.app.domain.models import (
    CyberRiskResult,
    DetectionResult,
    EvidenceRef,
    RiskFactor,
)
from risk_engine.profile import RiskProfile


def _saturate(value: float, scale: float) -> float:
    """Map [0, inf) to [0, 1) with a half-point at ``scale``."""
    if value <= 0.0:
        return 0.0
    return value / (value + scale)


class CyberRiskScorer:
    """Deterministic cyber-risk scorer."""

    def __init__(self, profile: RiskProfile) -> None:
        self.profile = profile
        self.cfg = profile.cyber_risk

    def score(
        self,
        detection: DetectionResult,
        evidence: list[EvidenceRef] | None = None,
    ) -> CyberRiskResult:
        evidence = evidence or []
        w = self.cfg["weights"]
        attack = detection.attack_type.value

        severity = float(self.cfg["attack_severity"][attack])
        confidence = float(detection.confidence)
        anomaly = _saturate(
            float(detection.anomaly_score or 0.0),
            float(self.cfg["anomaly_normalisation"]["scale"]),
        )
        propagation = float(self.cfg["propagation_potential"][attack])
        persistence = float(self.cfg["persistence"][attack])
        maturity = float(self.cfg["exploit_maturity"][attack])

        factors = [
            RiskFactor(
                name="attack_severity",
                value=severity,
                weight=float(w["attack_severity"]),
                contribution=severity * float(w["attack_severity"]),
                rationale=f"attack class {attack!r} carries severity {severity:.2f}",
                assertion_class=AssertionClass.INFERENCE,
            ),
            RiskFactor(
                name="detection_confidence",
                value=confidence,
                weight=float(w["detection_confidence"]),
                contribution=confidence * float(w["detection_confidence"]),
                rationale=(f"{detection.detector_name} reported confidence {confidence:.2f}"),
                assertion_class=AssertionClass.INFERENCE,
            ),
            RiskFactor(
                name="anomaly_magnitude",
                value=anomaly,
                weight=float(w["anomaly_magnitude"]),
                contribution=anomaly * float(w["anomaly_magnitude"]),
                rationale=(
                    f"anomaly score {detection.anomaly_score}"
                    if detection.anomaly_score is not None
                    else "no anomaly score available from this detector"
                ),
                assertion_class=AssertionClass.INFERENCE,
            ),
            RiskFactor(
                name="propagation_potential",
                value=propagation,
                weight=float(w["propagation_potential"]),
                contribution=propagation * float(w["propagation_potential"]),
                rationale=f"{attack!r} lateral-movement potential {propagation:.2f}",
                assertion_class=AssertionClass.INFERENCE,
            ),
            RiskFactor(
                name="persistence",
                value=persistence,
                weight=float(w["persistence"]),
                contribution=persistence * float(w["persistence"]),
                rationale=(
                    f"{attack!r} persistence {persistence:.2f}: "
                    + (
                        "survives traffic-level responses"
                        if persistence >= 0.6
                        else "addressable at the network layer"
                    )
                ),
                assertion_class=AssertionClass.INFERENCE,
            ),
            RiskFactor(
                name="exploit_maturity",
                value=maturity,
                weight=float(w["exploit_maturity"]),
                contribution=maturity * float(w["exploit_maturity"]),
                rationale=f"technique maturity {maturity:.2f}",
                assertion_class=AssertionClass.INFERENCE,
            ),
        ]

        score = sum(f.contribution for f in factors)
        score = max(0.0, min(1.0, score))

        uncertainty = self._uncertainty(detection, evidence)
        top = max(factors, key=lambda f: f.contribution)
        explanation = (
            f"Cyber risk {score:.2f} for {attack!r} on "
            f"{detection.device_id or 'unknown device'}. Dominant factor: "
            f"{top.name} ({top.contribution:.2f} of {score:.2f}). "
            f"Detector {detection.detector_name} "
            f"(confidence {confidence:.2f}). Uncertainty {uncertainty:.2f}."
        )

        return CyberRiskResult(
            score=round(score, 6),
            factors=factors,
            uncertainty=round(uncertainty, 6),
            explanation=explanation,
            formulation_version=self.profile.formulation_version,
        )

    def _uncertainty(self, detection: DetectionResult, evidence: list[EvidenceRef]) -> float:
        """Combine uncertainty sources into [0, 1].

        Surfaced rather than folded into the score, so the policy engine can
        require human approval when the evidence is thin even where the point
        estimate looks low.
        """
        u = self.cfg["uncertainty"]
        total = 0.0
        if detection.confidence < 0.6:
            total += float(u["low_confidence_weight"]) * (1.0 - detection.confidence)
        if detection.attack_type is AttackType.UNKNOWN:
            total += float(u["unknown_attack_weight"])
        if len(evidence) < int(u["sparse_evidence_threshold"]):
            deficit = 1.0 - len(evidence) / max(1, int(u["sparse_evidence_threshold"]))
            total += float(u["sparse_evidence_weight"]) * deficit
        return max(0.0, min(1.0, total))


__all__ = ["CyberRiskScorer"]
