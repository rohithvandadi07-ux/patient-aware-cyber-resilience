"""Clinical-risk scoring.

Answers "how much does the patient depend on this device, right now?"

This is the term that no public IoMT security dataset contains, and the
reason the closed-loop evaluation needs a simulator with clinical ground
truth. It is also where the central claim lives: the same attack on two
devices of equal cyber risk must produce different clinical risk, and
therefore a different response.

SAFETY ARCHITECTURE
-------------------
The weighted sum is augmented by **hard floors**. A purely additive model
can, with unlucky parameters, return a low clinical risk for a ventilator
sustaining a life-critical patient — and a low clinical risk is what
permits a drastic response. The floors make that unreachable regardless of
how the weights are swept, which is what lets the sensitivity analysis
explore the parameter space without ever producing an unsafe recommendation.

This is also why the floors are declared in the profile rather than
hard-coded: they are part of the published formulation, not hidden
engineering.

NOT CLINICAL GUIDANCE
---------------------
Every value here is a simulation parameter. Nothing in this module is a
clinical judgement, a triage rule or a standard of care.
"""

from __future__ import annotations

from backend.app.domain.enums import (
    AcuityLevel,
    CriticalityTier,
    DeviceOperationalState,
    PatientDependencyLevel,
)
from backend.app.domain.models import (
    ClinicalRiskResult,
    DeviceProfile,
    DeviceState,
    RiskFactor,
)
from risk_engine.profile import RiskProfile


class ClinicalRiskScorer:
    """Deterministic clinical-risk scorer."""

    def __init__(self, profile: RiskProfile) -> None:
        self.profile = profile
        self.cfg = profile.clinical_risk

    def score(
        self,
        device: DeviceProfile,
        state: DeviceState | None = None,
    ) -> ClinicalRiskResult:
        w = self.cfg["weights"]
        patient = device.patient

        # --- device criticality ------------------------------------------
        criticality = float(self.cfg["device_criticality"][device.criticality.value])

        # --- patient dependency, modulated by acuity ---------------------
        dependency_level = patient.dependency if patient else PatientDependencyLevel.NONE
        acuity = patient.acuity if patient else AcuityLevel.NONE
        dependency_base = float(self.cfg["patient_dependency"][dependency_level.value])
        acuity_mult = float(self.cfg["acuity_multiplier"][acuity.value])
        dependency = dependency_base * acuity_mult

        # --- life support -------------------------------------------------
        on_life_support = bool(patient.on_life_support) if patient else False
        life_support = (
            1.0
            if (device.life_support_relevant and on_life_support)
            else (0.5 if device.life_support_relevant else 0.0)
        )

        # --- operational state --------------------------------------------
        op_state = state.operational_state if state else DeviceOperationalState.ACTIVE
        operational = float(self.cfg["operational_state"][op_state.value])

        # --- redundancy deficit -------------------------------------------
        if not device.has_redundant_peer:
            redundancy_key = "no_peer"
        elif device.supports_safe_failover:
            redundancy_key = "peer_with_safe_failover"
        else:
            redundancy_key = "peer_without_safe_failover"
        redundancy_deficit = float(self.cfg["redundancy"][redundancy_key])

        # --- interruption intolerance -------------------------------------
        tolerance_minutes = (
            patient.tolerable_interruption_minutes
            if patient
            else device.acceptable_interruption_seconds / 60.0
        )
        intolerance = self._intolerance(tolerance_minutes)

        factors = [
            RiskFactor(
                name="device_criticality",
                value=criticality,
                weight=float(w["device_criticality"]),
                contribution=criticality * float(w["device_criticality"]),
                rationale=(
                    f"{device.device_type.value} classified "
                    f"{device.criticality.value} ({criticality:.2f})"
                ),
            ),
            RiskFactor(
                name="patient_dependency",
                value=dependency,
                weight=float(w["patient_dependency"]),
                contribution=dependency * float(w["patient_dependency"]),
                rationale=(
                    f"dependency {dependency_level.value} "
                    f"({dependency_base:.2f}) x acuity {acuity.value} "
                    f"({acuity_mult:.2f}) = {dependency:.2f}"
                    if patient
                    else "no patient attached to this device"
                ),
            ),
            RiskFactor(
                name="life_support",
                value=life_support,
                weight=float(w["life_support"]),
                contribution=life_support * float(w["life_support"]),
                rationale=(
                    "device is life-support relevant and the patient is currently on life support"
                    if life_support >= 1.0
                    else (
                        "device is life-support relevant but the patient is not "
                        "currently life-support dependent"
                        if life_support > 0.0
                        else "device has no life-support role"
                    )
                ),
            ),
            RiskFactor(
                name="operational_state",
                value=operational,
                weight=float(w["operational_state"]),
                contribution=operational * float(w["operational_state"]),
                rationale=(
                    f"device state {op_state.value} ({operational:.2f})"
                    + (
                        "; already degraded, so less headroom absorbs further loss"
                        if operational >= 0.7
                        else ""
                    )
                ),
            ),
            RiskFactor(
                name="redundancy_deficit",
                value=redundancy_deficit,
                weight=float(w["redundancy_deficit"]),
                contribution=redundancy_deficit * float(w["redundancy_deficit"]),
                rationale={
                    "no_peer": "no redundant peer: no safe clinical alternative",
                    "peer_without_safe_failover": (
                        "redundant peer exists but failover is not validated as safe"
                    ),
                    "peer_with_safe_failover": ("redundant peer with safe failover available"),
                }[redundancy_key],
            ),
            RiskFactor(
                name="interruption_intolerance",
                value=intolerance,
                weight=float(w["interruption_intolerance"]),
                contribution=intolerance * float(w["interruption_intolerance"]),
                rationale=(
                    f"tolerable interruption {tolerance_minutes:.1f} min "
                    f"-> intolerance {intolerance:.2f}"
                ),
            ),
        ]

        weighted = sum(f.contribution for f in factors)

        # --- hard floors ---------------------------------------------------
        floors = self.cfg["floors"]
        applied_floors: list[str] = []
        score = weighted

        delivering = bool(state.delivering_therapy) if state else True
        if device.life_support_relevant and on_life_support and delivering:
            floor = float(floors["life_support_active"])
            if score < floor:
                applied_floors.append(
                    f"life_support_active floor {floor:.2f} applied "
                    f"(weighted sum was {weighted:.2f})"
                )
                score = floor

        if dependency_level is PatientDependencyLevel.LIFE_CRITICAL:
            floor = float(floors["life_critical_dependency"])
            if score < floor:
                applied_floors.append(
                    f"life_critical_dependency floor {floor:.2f} applied (was {score:.2f})"
                )
                score = floor

        # Absence of a clinician is an additive bump, not a floor: it makes a
        # bad situation worse rather than defining a minimum.
        if patient is not None and not patient.clinician_present:
            bump = float(floors["no_clinician_present"])
            score += bump
            applied_floors.append(f"no clinician present: +{bump:.2f}")

        score = max(0.0, min(1.0, score))

        # --- uncertainty ---------------------------------------------------
        uncertainty = 0.0
        notes: list[str] = []
        if state is None:
            uncertainty += 0.25
            notes.append("device state unavailable; assumed ACTIVE")
        if patient is None and device.criticality not in {
            CriticalityTier.NON_CLINICAL,
            CriticalityTier.SUPPORTIVE,
        }:
            # A clinical device with no known patient context is a genuine
            # unknown, and failing safe means treating it as uncertain rather
            # than as unoccupied.
            uncertainty += 0.35
            notes.append("clinical device with no patient context; dependency unknown")
        uncertainty = min(1.0, uncertainty)

        top = max(factors, key=lambda f: f.contribution)
        explanation = (
            f"Clinical risk {score:.2f} for {device.device_id} "
            f"({device.criticality.value}). Dominant factor: {top.name} "
            f"({top.contribution:.2f}). "
            + (" ".join(applied_floors) + " " if applied_floors else "")
            + (" ".join(notes) if notes else "")
        ).strip()

        return ClinicalRiskResult(
            score=round(score, 6),
            factors=factors,
            uncertainty=round(uncertainty, 6),
            explanation=explanation,
            formulation_version=self.profile.formulation_version,
            life_support_involved=bool(device.life_support_relevant and on_life_support),
            patient_dependency=dependency_level,
        )

    def _intolerance(self, tolerable_minutes: float) -> float:
        cfg = self.cfg["interruption_intolerance"]
        zero = float(cfg["zero_tolerance_minutes"])
        full = float(cfg["full_tolerance_minutes"])
        if tolerable_minutes <= zero:
            return 1.0
        if tolerable_minutes >= full:
            return 0.0
        return 1.0 - (tolerable_minutes - zero) / (full - zero)


__all__ = ["ClinicalRiskScorer"]
