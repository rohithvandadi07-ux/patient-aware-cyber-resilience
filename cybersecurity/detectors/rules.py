"""Deterministic rule-based detector.

Serves three purposes:

1. **A floor baseline.** If an ML model cannot beat hand-written rules, the
   ML contributes nothing and should not be in the paper. Several published
   IoMT results omit this comparison; it is cheap and honest to include.
2. **Cold-start coverage.** The platform must detect something before any
   model is trained.
3. **Explainability.** Each firing names the rule and the observed values,
   which the investigation agent can cite as evidence.

Thresholds are declared data, not magic numbers buried in branches, so they
can be swept in the sensitivity analysis.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.domain.enums import AttackType, DetectorKind
from backend.app.domain.models import DetectionResult
from cybersecurity.detectors.base import Detector, DetectorMetadata
from cybersecurity.features.extractor import FeatureWindow


@dataclass(frozen=True)
class Rule:
    """One detection rule: all conditions must hold."""

    name: str
    attack_type: AttackType
    conditions: tuple[tuple[str, str, float], ...]
    confidence: float = 0.6
    rationale: str = ""

    def evaluate(self, features: dict[str, float]) -> tuple[bool, dict[str, float]]:
        matched: dict[str, float] = {}
        for feature, op, threshold in self.conditions:
            if feature not in features:
                return False, {}
            value = features[feature]
            ok = {
                ">": value > threshold,
                ">=": value >= threshold,
                "<": value < threshold,
                "<=": value <= threshold,
                "==": value == threshold,
            }[op]
            if not ok:
                return False, {}
            matched[feature] = value
        return True, matched


#: Default rule set. Thresholds are intentionally conservative: the rule
#: engine is a floor baseline, not the primary detector, and a rule engine
#: tuned to win would not be a fair baseline.
DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        name="volumetric_flood",
        attack_type=AttackType.DDOS,
        conditions=(("packets_per_second", ">", 8000.0), ("syn_ratio", ">", 0.5)),
        confidence=0.85,
        rationale="Sustained packet rate with predominantly SYN traffic",
    ),
    Rule(
        name="single_source_flood",
        attack_type=AttackType.DOS,
        conditions=(("packets_per_second", ">", 3000.0), ("syn_ratio", ">", 0.4)),
        confidence=0.7,
        rationale="Elevated packet rate with high SYN ratio from few sources",
    ),
    Rule(
        name="port_sweep",
        attack_type=AttackType.PORT_SCAN,
        conditions=(("distinct_dst_ports", ">", 25.0), ("syn_ratio", ">", 0.5)),
        confidence=0.75,
        rationale="Many distinct destination ports contacted with SYN probes",
    ),
    Rule(
        name="arp_cache_poisoning",
        attack_type=AttackType.ARP_SPOOFING,
        conditions=(("arp_table_changes", ">", 6.0), ("duplicate_mac_observed", ">=", 1.0)),
        confidence=0.7,
        rationale="ARP churn with an IP observed under conflicting MAC addresses",
    ),
    Rule(
        name="relay_latency_with_downgrade",
        attack_type=AttackType.MITM,
        conditions=(
            ("rtt_ms", ">", 25.0),
            ("ttl_variance", ">", 3.0),
            ("duplicate_mac_observed", ">=", 1.0),
        ),
        confidence=0.65,
        rationale="Relay-consistent latency and TTL variance with MAC conflict",
    ),
    Rule(
        name="unauthenticated_command",
        attack_type=AttackType.MALICIOUS_COMMAND,
        conditions=(("authenticated_session", "<=", 0.0), ("exceeds_safe_limit", ">=", 1.0)),
        confidence=0.9,
        rationale=(
            "Device command outside the safe envelope arrived without an authenticated session"
        ),
    ),
    Rule(
        name="offsegment_command",
        attack_type=AttackType.MALICIOUS_COMMAND,
        conditions=(("source_offsegment", ">=", 1.0), ("authenticated_session", "<=", 0.0)),
        confidence=0.75,
        rationale="Unauthenticated device command from outside the clinical segment",
    ),
    Rule(
        name="support_reduction_command",
        attack_type=AttackType.MALICIOUS_COMMAND,
        conditions=(("reduces_support", ">=", 1.0), ("authenticated_session", "<=", 0.0)),
        confidence=0.9,
        rationale="Unauthenticated command reducing therapeutic support",
    ),
    Rule(
        name="brute_force_success",
        attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
        conditions=(("failed_attempts", ">", 15.0), ("auth_after_failures", ">=", 1.0)),
        confidence=0.85,
        rationale="Authentication succeeded after a run of failures",
    ),
    Rule(
        name="credential_guessing",
        attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
        conditions=(("failed_attempts", ">", 25.0),),
        confidence=0.6,
        rationale="High authentication failure count in one window",
    ),
    Rule(
        name="mass_encryption",
        attack_type=AttackType.RANSOMWARE_BEHAVIOUR,
        conditions=(
            ("encrypted_file_ops", ">", 120.0),
            ("disk_write_mb_s", ">", 60.0),
            ("cpu_pct", ">", 70.0),
        ),
        confidence=0.85,
        rationale="Mass encrypted file operations with sustained disk and CPU load",
    ),
    Rule(
        name="telemetry_too_smooth",
        attack_type=AttackType.SPOOFED_TELEMETRY,
        conditions=(("telemetry_variance_ratio", "<", 0.25),),
        confidence=0.55,
        rationale=(
            "Reported telemetry variance far below the device's established "
            "baseline, consistent with synthesised values"
        ),
    ),
    Rule(
        name="telemetry_residual_spike",
        attack_type=AttackType.SPOOFED_TELEMETRY,
        conditions=(("telemetry_residual", ">", 6.0),),
        confidence=0.5,
        rationale="Telemetry deviates sharply from its short-run forecast",
    ),
)


class RuleDetector(Detector):
    """Evaluates the rule set, reporting the highest-confidence match."""

    def __init__(self, rules: tuple[Rule, ...] = DEFAULT_RULES, name: str = "rule_engine"):
        super().__init__(
            DetectorMetadata(
                name=name,
                kind=DetectorKind.RULE_ENGINE,
                model_version="rules-v1",
                hyperparameters={"rule_count": len(rules)},
            )
        )
        self.rules = rules

    def predict_window(self, window: FeatureWindow) -> DetectionResult:
        hits: list[tuple[Rule, dict[str, float]]] = []
        for rule in self.rules:
            ok, matched = rule.evaluate(window.features)
            if ok:
                hits.append((rule, matched))

        if not hits:
            return self._result(
                window,
                is_attack=False,
                attack_type=AttackType.NONE,
                confidence=0.0,
                notes="no rule matched",
            )

        hits.sort(key=lambda h: h[0].confidence, reverse=True)
        rule, matched = hits[0]
        # Corroboration across independent rules raises confidence, capped so
        # a rule engine never reports certainty.
        corroboration = min(0.1, 0.05 * (len(hits) - 1))
        return self._result(
            window,
            is_attack=True,
            attack_type=rule.attack_type,
            confidence=min(0.95, rule.confidence + corroboration),
            class_scores={r.attack_type.value: r.confidence for r, _ in hits},
            contributing=matched,
            notes=f"{rule.name}: {rule.rationale}"
            + (f" (+{len(hits) - 1} corroborating)" if len(hits) > 1 else ""),
        )


__all__ = ["DEFAULT_RULES", "Rule", "RuleDetector"]
