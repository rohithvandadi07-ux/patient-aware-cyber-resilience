"""Response-impact scoring.

Answers "what would **this specific response** cost, clinically?"

This is the term that distinguishes the work. Prior IoMT IDS work that acts
at all selects a response by security benefit; it does not weigh the cost of
its own action against the care the device is delivering. The 2026 gap
analysis cited in docs/related-work.md found no analysis of impact-aware
response in the literature it surveyed.

The key mechanism is that a response's clinical cost is **contextual**: the
same action is near-free on a workstation and potentially fatal on a
ventilator. So a base cost per action is modulated by the device's clinical
weight, its redundancy, and whether the interruption fits inside what the
device and patient can absorb.
"""

from __future__ import annotations

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    ImpactClass,
    PatientDependencyLevel,
    ResponseActionType,
)
from backend.app.domain.models import (
    ClinicalRiskResult,
    DeviceProfile,
    DeviceState,
    ResponseCandidate,
    ResponseImpactResult,
    RiskFactor,
)
from risk_engine.profile import RiskProfile

#: Actions that interrupt therapy delivery on the target device. Separated
#: from the cost table because the policy engine hard-gates on this set:
#: a therapy-interrupting action on a life-sustaining device is categorically
#: different from an expensive-but-non-interrupting one.
THERAPY_INTERRUPTING: frozenset[ResponseActionType] = frozenset(
    {
        ResponseActionType.SHUTDOWN_DEVICE,
        ResponseActionType.RESTART_DEVICE_SERVICE,
        ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE,
    }
)

#: Actions that sever or restrict the device's network path. These do not
#: stop therapy on a device that fails safe locally, but they do remove
#: remote monitoring and control - itself a clinical risk.
CONNECTIVITY_AFFECTING: frozenset[ResponseActionType] = frozenset(
    {
        ResponseActionType.QUARANTINE_DEVICE,
        ResponseActionType.ISOLATE_NETWORK_SEGMENT,
        ResponseActionType.RESTRICT_COMMUNICATION,
    }
)


class ResponseImpactScorer:
    """Deterministic per-candidate impact scorer."""

    def __init__(self, profile: RiskProfile) -> None:
        self.profile = profile
        self.cfg = profile.response_impact

    def score(
        self,
        candidate: ResponseCandidate,
        device: DeviceProfile | None,
        state: DeviceState | None,
        clinical_risk: ClinicalRiskResult | None,
        attack_type: AttackType = AttackType.UNKNOWN,
    ) -> ResponseImpactResult:
        action = candidate.action_type
        key = action.value
        w = self.cfg["weights"]

        # Security benefit is the containment ceiling scaled by how well the
        # action severs THIS attack's mechanism. Without this, the engine
        # selects whichever action has the best fixed benefit-to-cost ratio
        # regardless of the attack - which made it choose credential
        # rotation against a volumetric flood.
        ceiling = float(self.cfg["security_benefit"][key])
        effectiveness = self._effectiveness(attack_type, action)
        security_benefit = ceiling * effectiveness
        base_cost = float(self.cfg["clinical_cost_base"][key])
        interruption_s = float(self.cfg["interruption_seconds"][key])
        reversible = bool(self.cfg["reversible"][key])

        factors: list[RiskFactor] = []

        # --- contextual clinical cost ------------------------------------
        # The device's clinical weight scales the base cost. Without a
        # device profile we fail safe by assuming high clinical weight.
        clinical_weight = clinical_risk.score if clinical_risk else 0.75
        context_note = (
            f"clinical risk {clinical_weight:.2f} scales base cost {base_cost:.2f}"
            if clinical_risk
            else "no clinical context available; assuming high clinical weight (fail-safe)"
        )
        clinical_cost = base_cost * clinical_weight

        # --- redundancy discount ------------------------------------------
        discount_applied = False
        if (
            device is not None
            and device.has_redundant_peer
            and device.supports_safe_failover
            and action in THERAPY_INTERRUPTING
        ):
            discount = float(self.cfg["redundancy_discount"])
            clinical_cost *= 1.0 - discount
            discount_applied = True

        # --- interruption tolerance ---------------------------------------
        # An interruption that fits inside what the device can absorb costs
        # much less than one that exceeds it. This is the mechanism by which
        # a 20-second failover on a redundant ventilator is acceptable while
        # an indefinite shutdown is not.
        acceptable_s = device.acceptable_interruption_seconds if device else 0.0
        patient_tolerance_s = (
            device.patient.tolerable_interruption_minutes * 60.0
            if device and device.patient
            else acceptable_s
        )
        budget_s = min(acceptable_s, patient_tolerance_s) if device else 0.0
        if interruption_s <= 0.0:
            overrun = 0.0
        elif budget_s <= 0.0:
            overrun = 1.0
        else:
            overrun = min(1.0, max(0.0, (interruption_s - budget_s) / max(budget_s, 1.0)))
        clinical_cost = min(1.0, clinical_cost * (1.0 + 0.6 * overrun))

        # --- therapy interruption escalation ------------------------------
        #
        # ORDERING MATTERS. The life-support floor must NOT clobber the
        # redundancy discount: failover to a validated, working peer is
        # precisely the case where interrupting the compromised device is
        # clinically acceptable, and is the mechanism by which a hospital
        # with redundancy can defend itself more aggressively than one
        # without. So the floor applies only when NO safe alternative exists.
        interrupts_therapy = action in THERAPY_INTERRUPTING and bool(
            state.delivering_therapy if state else True
        )
        safe_alternative = discount_applied or (
            action is ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE
            and device is not None
            and device.has_redundant_peer
            and device.supports_safe_failover
        )
        if interrupts_therapy and not safe_alternative and clinical_risk:
            if clinical_risk.life_support_involved:
                # Interrupting life-sustaining therapy with no alternative is
                # the worst case this engine can express, and no weight sweep
                # may soften it.
                clinical_cost = max(clinical_cost, 0.95)
            elif clinical_risk.patient_dependency is PatientDependencyLevel.LIFE_CRITICAL:
                clinical_cost = max(clinical_cost, 0.90)

        clinical_cost = max(0.0, min(1.0, clinical_cost))

        # --- duration term -------------------------------------------------
        duration_term = min(1.0, interruption_s / 300.0) if interruption_s > 0 else 0.0

        factors.extend(
            [
                RiskFactor(
                    name="security_benefit",
                    value=security_benefit,
                    weight=float(w["security_benefit"]),
                    contribution=security_benefit * float(w["security_benefit"]),
                    rationale=(
                        f"{key} containment ceiling {ceiling:.2f} x mechanism "
                        f"effectiveness {effectiveness:.2f} against "
                        f"{attack_type.value} = {security_benefit:.2f}"
                        + (
                            "; this action does not address the attack mechanism"
                            if effectiveness < 0.35
                            else ""
                        )
                    ),
                    assertion_class=AssertionClass.INFERENCE,
                ),
                RiskFactor(
                    name="clinical_cost",
                    value=clinical_cost,
                    weight=float(w["clinical_cost"]),
                    contribution=clinical_cost * float(w["clinical_cost"]),
                    rationale=(
                        f"{context_note}"
                        + ("; redundancy discount applied" if discount_applied else "")
                        + (
                            f"; interruption {interruption_s:.0f}s exceeds {budget_s:.0f}s budget"
                            if overrun > 0
                            else ""
                        )
                        + (
                            "; INTERRUPTS LIFE-SUSTAINING THERAPY"
                            if interrupts_therapy
                            and clinical_risk
                            and clinical_risk.life_support_involved
                            else ""
                        )
                    ),
                ),
                RiskFactor(
                    name="reversibility",
                    value=0.0 if reversible else 1.0,
                    weight=float(w["reversibility"]),
                    contribution=(0.0 if reversible else 1.0) * float(w["reversibility"]),
                    rationale=(
                        "action is reversible"
                        if reversible
                        else "action is NOT reversible; in-flight therapy state is lost"
                    ),
                ),
                RiskFactor(
                    name="duration",
                    value=duration_term,
                    weight=float(w["duration"]),
                    contribution=duration_term * float(w["duration"]),
                    rationale=f"expected interruption {interruption_s:.0f}s",
                ),
            ]
        )

        impact_class = self._classify(
            clinical_cost, interrupts_therapy, clinical_risk, safe_alternative
        )

        explanation = (
            f"{key} vs {attack_type.value}: security benefit "
            f"{security_benefit:.2f} (ceiling {ceiling:.2f} x effectiveness "
            f"{effectiveness:.2f}), clinical cost "
            f"{clinical_cost:.2f} -> impact {impact_class.value}. "
            f"Interruption {interruption_s:.0f}s vs budget {budget_s:.0f}s. "
            f"{'Reversible' if reversible else 'Irreversible'}."
            + (" Safe failover available." if discount_applied else "")
        )

        return ResponseImpactResult(
            action_type=action,
            security_benefit=round(security_benefit, 6),
            clinical_impact=round(clinical_cost, 6),
            service_interruption_seconds=interruption_s,
            reversible=reversible,
            backup_available=bool(device.has_redundant_peer and device.supports_safe_failover)
            if device
            else False,
            impact_class=impact_class,
            factors=factors,
            explanation=explanation,
            formulation_version=self.profile.formulation_version,
        )

    def _effectiveness(self, attack_type: AttackType, action: ResponseActionType) -> float:
        """How well ``action`` severs ``attack_type``'s mechanism, in [0, 1]."""
        table = self.cfg.get("mechanism_effectiveness", {})
        per_attack = table.get(attack_type.value)
        if not per_attack:
            return 1.0
        if action.value in per_attack:
            return float(per_attack[action.value])
        return float(per_attack.get("default", 1.0))

    def _classify(
        self,
        clinical_cost: float,
        interrupts_therapy: bool,
        clinical_risk: ClinicalRiskResult | None,
        safe_alternative: bool = False,
    ) -> ImpactClass:
        """Classify impact, with a categorical UNSAFE gate.

        The gate is categorical rather than threshold-based for the one case
        the project exists to prevent: interrupting life-sustaining therapy
        **with no safe alternative**. No parameter sweep can reclassify that
        as merely HIGH. Where a validated failover peer exists, the same
        action is not categorically unsafe and is scored on its merits.
        """
        if (
            interrupts_therapy
            and not safe_alternative
            and clinical_risk is not None
            and clinical_risk.life_support_involved
            and not clinical_risk.score < 0.5
        ):
            return ImpactClass.UNSAFE

        t = self.cfg["impact_class_thresholds"]
        if clinical_cost <= float(t["low_max"]):
            return ImpactClass.LOW
        if clinical_cost <= float(t["moderate_max"]):
            return ImpactClass.MODERATE
        if clinical_cost <= float(t["high_max"]):
            return ImpactClass.HIGH
        return ImpactClass.UNSAFE


__all__ = ["CONNECTIVITY_AFFECTING", "THERAPY_INTERRUPTING", "ResponseImpactScorer"]
