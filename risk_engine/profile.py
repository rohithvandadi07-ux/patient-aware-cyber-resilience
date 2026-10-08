"""Risk-profile loading and validation.

The profile is declared configuration, not code, so that every parameter can
be swept in the sensitivity analysis and cited in the paper. Validation is
strict: a profile whose weights do not sum to 1.0, or that is missing a term
for an enum member, is rejected at load time rather than silently producing
out-of-range scores.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from backend.app.domain.enums import (
    AcuityLevel,
    AttackType,
    CriticalityTier,
    DeviceOperationalState,
    PatientDependencyLevel,
    ResponseActionType,
)

DEFAULT_PROFILE_PATH = Path("configs/risk_profile.default.yaml")

#: Tolerance on weight-sum validation.
WEIGHT_SUM_TOLERANCE = 1e-6


class ProfileValidationError(ValueError):
    """Raised when a risk profile is internally inconsistent."""


@dataclass(frozen=True)
class RiskProfile:
    """A validated risk formulation."""

    formulation_version: str
    cyber_risk: dict[str, Any]
    clinical_risk: dict[str, Any]
    response_impact: dict[str, Any]
    decision: dict[str, Any]
    description: str = ""
    source_path: str | None = None

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str | None = None) -> RiskProfile:
        missing = [
            k
            for k in (
                "formulation_version",
                "cyber_risk",
                "clinical_risk",
                "response_impact",
                "decision",
            )
            if k not in data
        ]
        if missing:
            raise ProfileValidationError(f"risk profile is missing sections: {missing}")
        profile = cls(
            formulation_version=str(data["formulation_version"]),
            cyber_risk=data["cyber_risk"],
            clinical_risk=data["clinical_risk"],
            response_impact=data["response_impact"],
            decision=data["decision"],
            description=str(data.get("description", "")),
            source_path=source_path,
        )
        profile.validate()
        return profile

    @classmethod
    def load(cls, path: str | Path | None = None) -> RiskProfile:
        p = Path(path) if path else DEFAULT_PROFILE_PATH
        if not p.exists():
            raise FileNotFoundError(
                f"risk profile not found at {p}. The engine refuses to run with "
                "built-in defaults, because an unreported parameter set cannot "
                "be reproduced or cited."
            )
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        return cls.from_dict(data, source_path=str(p))

    # -- validation --------------------------------------------------------
    def validate(self) -> None:
        self._check_weights("cyber_risk", self.cyber_risk)
        self._check_weights("clinical_risk", self.clinical_risk)
        self._check_weights("response_impact", self.response_impact)

        # Decision weights
        d = self.decision
        total = float(d["security_gain_weight"]) + float(d["clinical_cost_weight"])
        if abs(total - 1.0) > WEIGHT_SUM_TOLERANCE:
            raise ProfileValidationError(
                f"decision security_gain_weight + clinical_cost_weight = {total}, "
                "expected 1.0 so the score stays interpretable"
            )

        # Enum coverage: every member must have a value, or scoring would
        # silently fall back to a default and the profile would not describe
        # what the engine actually did.
        self._check_coverage(
            "cyber_risk.attack_severity", self.cyber_risk["attack_severity"], AttackType
        )
        self._check_coverage(
            "cyber_risk.propagation_potential",
            self.cyber_risk["propagation_potential"],
            AttackType,
        )
        self._check_coverage("cyber_risk.persistence", self.cyber_risk["persistence"], AttackType)
        self._check_coverage(
            "cyber_risk.exploit_maturity", self.cyber_risk["exploit_maturity"], AttackType
        )
        self._check_coverage(
            "clinical_risk.device_criticality",
            self.clinical_risk["device_criticality"],
            CriticalityTier,
        )
        self._check_coverage(
            "clinical_risk.patient_dependency",
            self.clinical_risk["patient_dependency"],
            PatientDependencyLevel,
        )
        self._check_coverage(
            "clinical_risk.acuity_multiplier",
            self.clinical_risk["acuity_multiplier"],
            AcuityLevel,
        )
        self._check_coverage(
            "clinical_risk.operational_state",
            self.clinical_risk["operational_state"],
            DeviceOperationalState,
        )
        for key in ("security_benefit", "clinical_cost_base", "interruption_seconds", "reversible"):
            self._check_coverage(
                f"response_impact.{key}", self.response_impact[key], ResponseActionType
            )

        self._check_mechanism_effectiveness()
        self._check_unit_range()

    @staticmethod
    def _check_weights(name: str, block: dict[str, Any]) -> None:
        weights = block.get("weights")
        if not weights:
            raise ProfileValidationError(f"{name} has no weights block")
        total = sum(float(v) for v in weights.values())
        if abs(total - 1.0) > WEIGHT_SUM_TOLERANCE:
            raise ProfileValidationError(
                f"{name} weights sum to {total:.6f}, expected 1.0. A convex "
                "combination is what guarantees the score lands in [0, 1]."
            )
        negative = [k for k, v in weights.items() if float(v) < 0]
        if negative:
            raise ProfileValidationError(f"{name} has negative weights: {negative}")

    def _check_mechanism_effectiveness(self) -> None:
        """Every attack needs an effectiveness row, with values in [0, 1]."""
        table = self.response_impact.get("mechanism_effectiveness")
        if not table:
            raise ProfileValidationError(
                "response_impact.mechanism_effectiveness is required. Without it "
                "an action's security benefit is independent of the attack, and "
                "the engine selects the same response for every threat."
            )
        required = {m.value for m in AttackType}
        missing = sorted(required - set(table))
        if missing:
            raise ProfileValidationError(
                f"mechanism_effectiveness is missing attack types: {missing}"
            )
        valid_actions = {m.value for m in ResponseActionType} | {"default"}
        for attack, row in table.items():
            unknown = sorted(set(row) - valid_actions)
            if unknown:
                raise ProfileValidationError(
                    f"mechanism_effectiveness[{attack}] has unknown keys: {unknown}"
                )
            bad = {k: v for k, v in row.items() if not 0.0 <= float(v) <= 1.0}
            if bad:
                raise ProfileValidationError(
                    f"mechanism_effectiveness[{attack}] values outside [0,1]: {bad}"
                )

    @staticmethod
    def _check_coverage(name: str, mapping: dict[str, Any], enum_cls: type) -> None:
        declared = set(mapping)
        required = {m.value for m in enum_cls}
        missing = sorted(required - declared)
        if missing:
            raise ProfileValidationError(
                f"{name} is missing entries for {missing}. Every enum member needs "
                "an explicit value; a silent default would make the profile an "
                "inaccurate description of what the engine computed."
            )
        unknown = sorted(declared - required)
        if unknown:
            raise ProfileValidationError(
                f"{name} has entries not in {enum_cls.__name__}: {unknown}"
            )

    def _check_unit_range(self) -> None:
        """Factor tables that feed a convex combination must be in [0, 1]."""
        unit_tables = [
            ("cyber_risk.attack_severity", self.cyber_risk["attack_severity"]),
            ("cyber_risk.propagation_potential", self.cyber_risk["propagation_potential"]),
            ("cyber_risk.persistence", self.cyber_risk["persistence"]),
            ("cyber_risk.exploit_maturity", self.cyber_risk["exploit_maturity"]),
            ("clinical_risk.device_criticality", self.clinical_risk["device_criticality"]),
            ("clinical_risk.patient_dependency", self.clinical_risk["patient_dependency"]),
            ("clinical_risk.acuity_multiplier", self.clinical_risk["acuity_multiplier"]),
            ("clinical_risk.operational_state", self.clinical_risk["operational_state"]),
            ("clinical_risk.redundancy", self.clinical_risk["redundancy"]),
            ("response_impact.security_benefit", self.response_impact["security_benefit"]),
            ("response_impact.clinical_cost_base", self.response_impact["clinical_cost_base"]),
        ]
        for name, table in unit_tables:
            bad = {k: v for k, v in table.items() if not 0.0 <= float(v) <= 1.0}
            if bad:
                raise ProfileValidationError(f"{name} has values outside [0, 1]: {bad}")

    # -- accessors ---------------------------------------------------------
    def fingerprint(self) -> str:
        """Hash of the whole profile, recorded in every risk result.

        Lets any published number be traced to the exact parameter set that
        produced it.
        """
        from backend.app.domain.ids import canonical_hash

        return canonical_hash(
            {
                "formulation_version": self.formulation_version,
                "cyber_risk": self.cyber_risk,
                "clinical_risk": self.clinical_risk,
                "response_impact": self.response_impact,
                "decision": self.decision,
            }
        )[:16]

    def with_overrides(self, overrides: dict[str, Any]) -> RiskProfile:
        """Return a new profile with dotted-path overrides applied.

        Used by the sensitivity analysis, e.g.
        ``{"decision.clinical_cost_weight": 0.8,
           "decision.security_gain_weight": 0.2}``.
        """
        import copy

        data = {
            "formulation_version": self.formulation_version,
            "description": self.description,
            "cyber_risk": copy.deepcopy(self.cyber_risk),
            "clinical_risk": copy.deepcopy(self.clinical_risk),
            "response_impact": copy.deepcopy(self.response_impact),
            "decision": copy.deepcopy(self.decision),
        }
        for dotted, value in overrides.items():
            parts = dotted.split(".")
            node: Any = data
            for part in parts[:-1]:
                if part not in node:
                    raise KeyError(f"override path {dotted!r} not found at {part!r}")
                node = node[part]
            node[parts[-1]] = value
        return RiskProfile.from_dict(data, source_path=f"{self.source_path}+overrides")


def load_default_profile() -> RiskProfile:
    return RiskProfile.load()


__all__ = [
    "DEFAULT_PROFILE_PATH",
    "ProfileValidationError",
    "RiskProfile",
    "load_default_profile",
]
