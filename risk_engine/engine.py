"""The patient-aware dual-risk decision engine.

This module is the central research artefact. It takes a detection, a device
profile, a device state and a set of candidate responses, and produces a
:class:`PatientAwareDecision` recording:

* the cyber risk,
* the clinical risk,
* the impact of **every** candidate considered,
* the selected action and why,
* and the **counterfactual**: what a cyber-risk-only defender would have
  chosen.

That last element is what makes the contribution measurable rather than
asserted. The evaluation framework reports the divergence rate between
patient-aware and cyber-only selection, and the clinical harm avoided on
the cases where they diverge.

AUTHORITY
---------
This engine is deterministic and authoritative. The agentic layer may
investigate, reason and propose candidates; it cannot alter a score produced
here, and it cannot select an action this engine classifies as unsafe. The
policy engine (``response_engine``) then decides whether the selected action
may be taken autonomously, needs approval, or is denied outright.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    ImpactClass,
    ResponseActionType,
    RiskBand,
)
from backend.app.domain.models import (
    ClinicalRiskResult,
    CyberRiskResult,
    DetectionResult,
    DeviceProfile,
    DeviceState,
    EvidenceRef,
    PatientAwareDecision,
    ResponseCandidate,
    ResponseImpactResult,
)
from risk_engine.clinical import ClinicalRiskScorer
from risk_engine.cyber import CyberRiskScorer
from risk_engine.impact import ResponseImpactScorer
from risk_engine.profile import RiskProfile, load_default_profile


@dataclass
class ScoredCandidate:
    """A candidate with its impact assessment and decision score."""

    candidate: ResponseCandidate
    impact: ResponseImpactResult
    score: float
    security_term: float
    clinical_term: float
    inaction_term: float
    admissible: bool
    rejection_reason: str = ""


class PatientAwareRiskEngine:
    """Deterministic dual-risk decision engine."""

    def __init__(self, profile: RiskProfile | None = None) -> None:
        self.profile = profile or load_default_profile()
        self.cyber = CyberRiskScorer(self.profile)
        self.clinical = ClinicalRiskScorer(self.profile)
        self.impact = ResponseImpactScorer(self.profile)
        self.decision_cfg = self.profile.decision

    # -- individual terms --------------------------------------------------
    def cyber_risk(
        self, detection: DetectionResult, evidence: list[EvidenceRef] | None = None
    ) -> CyberRiskResult:
        return self.cyber.score(detection, evidence)

    def clinical_risk(
        self, device: DeviceProfile, state: DeviceState | None = None
    ) -> ClinicalRiskResult:
        return self.clinical.score(device, state)

    def response_impact(
        self,
        candidate: ResponseCandidate,
        device: DeviceProfile | None,
        state: DeviceState | None,
        clinical_risk: ClinicalRiskResult | None,
        attack_type: AttackType = AttackType.UNKNOWN,
    ) -> ResponseImpactResult:
        return self.impact.score(candidate, device, state, clinical_risk, attack_type)

    # -- the decision ------------------------------------------------------
    def decide(
        self,
        incident_id: str,
        decided_at: datetime,
        detection: DetectionResult,
        device: DeviceProfile | None,
        state: DeviceState | None,
        candidates: list[ResponseCandidate],
        evidence: list[EvidenceRef] | None = None,
        exhausted_actions: list[ResponseActionType] | None = None,
        patient_aware: bool = True,
    ) -> PatientAwareDecision:
        """Produce the dual-risk decision record.

        ``patient_aware=False`` runs the cyber-only ablation through the same
        code path, which is what keeps the ablation honest: the comparison
        differs only in whether clinical terms enter the objective, not in
        which implementation is used.
        """
        exhausted = set(exhausted_actions or [])
        cyber = self.cyber_risk(detection, evidence)
        clin = self.clinical_risk(device, state) if device is not None else self._unknown_clinical()

        scored = [
            self._score_candidate(
                c,
                device,
                state,
                clin,
                cyber,
                exhausted,
                patient_aware,
                detection.attack_type,
            )
            for c in candidates
        ]

        admissible = [s for s in scored if s.admissible]
        if admissible:
            best = max(admissible, key=lambda s: s.score)
        else:
            # Fail safe: when nothing is admissible, escalate to humans
            # rather than acting. This is a deliberate design choice - the
            # alternative (pick the least-bad inadmissible action) would mean
            # the engine can take an action it has itself judged unsafe.
            best = self._fallback_candidate(device, state, clin, cyber, detection.attack_type)
            scored.append(best)

        # --- counterfactual: what would a cyber-only defender choose? -----
        cyber_only_action: ResponseActionType | None = None
        diverged = False
        divergence_reason = ""
        if patient_aware:
            cyber_only = self._cyber_only_choice(scored)
            if cyber_only is not None:
                cyber_only_action = cyber_only.candidate.action_type
                diverged = cyber_only_action != best.candidate.action_type
                if diverged:
                    divergence_reason = (
                        f"A security-only objective would select "
                        f"{cyber_only_action.value} (security benefit "
                        f"{cyber_only.impact.security_benefit:.2f}, clinical cost "
                        f"{cyber_only.impact.clinical_impact:.2f}, impact "
                        f"{cyber_only.impact.impact_class.value}). Patient-aware "
                        f"selection chose {best.candidate.action_type.value} "
                        f"(security {best.impact.security_benefit:.2f}, clinical "
                        f"cost {best.impact.clinical_impact:.2f}, impact "
                        f"{best.impact.impact_class.value}) because clinical risk "
                        f"is {clin.score:.2f} ({clin.band.value})"
                        + (
                            " and the patient is life-critically dependent on this device."
                            if clin.life_support_involved
                            else "."
                        )
                    )

        rationale = self._rationale(best, cyber, clin, scored, patient_aware)

        return PatientAwareDecision(
            incident_id=incident_id,
            decided_at=decided_at,
            cyber_risk=cyber,
            clinical_risk=clin,
            candidate_impacts=[s.impact for s in scored],
            selected_action=best.candidate.action_type,
            decision_score=round(best.score, 6),
            decision_band=self._band(best.score),
            rationale=rationale,
            cyber_only_action=cyber_only_action,
            diverged_from_cyber_only=diverged,
            divergence_reason=divergence_reason,
            formulation_version=self.profile.formulation_version,
            assertion_class=AssertionClass.RECOMMENDATION,
        )

    # -- internals ---------------------------------------------------------
    def _score_candidate(
        self,
        candidate: ResponseCandidate,
        device: DeviceProfile | None,
        state: DeviceState | None,
        clin: ClinicalRiskResult,
        cyber: CyberRiskResult,
        exhausted: set[ResponseActionType],
        patient_aware: bool,
        attack_type: AttackType = AttackType.UNKNOWN,
    ) -> ScoredCandidate:
        impact = self.response_impact(candidate, device, state, clin, attack_type)
        d = self.decision_cfg

        security_term = float(d["security_gain_weight"]) * impact.security_benefit
        clinical_term = (
            float(d["clinical_cost_weight"]) * impact.clinical_impact if patient_aware else 0.0
        )
        # Penalty for leaving a serious attack unaddressed, so that
        # patient-awareness does not collapse into always choosing
        # monitor_only. Scales with cyber risk and with how little the
        # candidate actually achieves.
        inaction_term = (
            float(d["inaction_penalty_weight"]) * cyber.score * (1.0 - impact.security_benefit)
        )

        score = security_term - clinical_term - inaction_term

        admissible = True
        reason = ""
        if impact.impact_class is ImpactClass.UNSAFE and patient_aware:
            admissible = False
            reason = f"classified UNSAFE: {impact.explanation}"
        elif candidate.action_type in exhausted:
            admissible = False
            reason = (
                "already attempted for this incident and did not achieve "
                "recovery; re-planning must select a different action"
            )

        return ScoredCandidate(
            candidate=candidate,
            impact=impact,
            score=score,
            security_term=security_term,
            clinical_term=clinical_term,
            inaction_term=inaction_term,
            admissible=admissible,
            rejection_reason=reason,
        )

    def _cyber_only_choice(self, scored: list[ScoredCandidate]) -> ScoredCandidate | None:
        """What a security-only objective would pick.

        Maximises security benefit, ignoring clinical cost and the UNSAFE
        classification entirely - which is precisely the behaviour this work
        argues is unsafe in a clinical setting.
        """
        if not scored:
            return None
        return max(scored, key=lambda s: s.impact.security_benefit)

    def _fallback_candidate(
        self,
        device: DeviceProfile | None,
        state: DeviceState | None,
        clin: ClinicalRiskResult,
        cyber: CyberRiskResult,
        attack_type: AttackType = AttackType.UNKNOWN,
    ) -> ScoredCandidate:
        """Escalate to clinical staff when no candidate is admissible."""
        candidate = ResponseCandidate(
            action_type=ResponseActionType.ESCALATE_TO_CLINICAL_STAFF,
            target_device_id=device.device_id if device else None,
            proposed_by="risk_engine_failsafe",
            rationale=(
                "No candidate response was admissible: every option was either "
                "classified unsafe for this patient or already attempted. "
                "Escalating to clinical staff rather than taking an action the "
                "engine has judged unsafe."
            ),
        )
        impact = self.response_impact(candidate, device, state, clin, attack_type)
        return ScoredCandidate(
            candidate=candidate,
            impact=impact,
            score=0.0,
            security_term=0.0,
            clinical_term=0.0,
            inaction_term=0.0,
            admissible=True,
            rejection_reason="",
        )

    def _unknown_clinical(self) -> ClinicalRiskResult:
        """Fail-safe clinical risk when no device profile is available.

        Deliberately high: an unknown clinical context must not permit a
        drastic action. Uncertainty is maximal so the policy engine can
        require approval.
        """
        from backend.app.domain.enums import PatientDependencyLevel

        return ClinicalRiskResult(
            score=0.75,
            factors=[],
            uncertainty=1.0,
            explanation=(
                "No device profile available. Clinical risk set to a fail-safe "
                "high value and uncertainty to maximum: an unknown clinical "
                "context must not permit a drastic response."
            ),
            formulation_version=self.profile.formulation_version,
            life_support_involved=False,
            patient_dependency=PatientDependencyLevel.NONE,
        )

    def _band(self, score: float) -> RiskBand:
        b = self.decision_cfg["bands"]
        # The decision score can be negative (clinical cost exceeding
        # security gain), so it is shifted into [0,1] for banding.
        norm = max(0.0, min(1.0, (score + 1.0) / 2.0))
        if norm <= float(b["negligible_max"]):
            return RiskBand.NEGLIGIBLE
        if norm <= float(b["low_max"]):
            return RiskBand.LOW
        if norm <= float(b["moderate_max"]):
            return RiskBand.MODERATE
        if norm <= float(b["high_max"]):
            return RiskBand.HIGH
        return RiskBand.SEVERE

    def _rationale(
        self,
        best: ScoredCandidate,
        cyber: CyberRiskResult,
        clin: ClinicalRiskResult,
        scored: list[ScoredCandidate],
        patient_aware: bool,
    ) -> str:
        rejected = [s for s in scored if not s.admissible]
        parts = [
            f"Selected {best.candidate.action_type.value}.",
            f"Cyber risk {cyber.score:.2f} ({cyber.band.value}),"
            f" clinical risk {clin.score:.2f} ({clin.band.value}).",
            f"Candidate score {best.score:+.3f} = security {best.security_term:+.3f}"
            f" - clinical {best.clinical_term:.3f}"
            f" - inaction {best.inaction_term:.3f}.",
        ]
        if not patient_aware:
            parts.append(
                "ABLATION: clinical terms were excluded from the objective (patient_aware=False)."
            )
        if rejected:
            names = ", ".join(
                f"{s.candidate.action_type.value} ({s.rejection_reason.split(':')[0]})"
                for s in rejected
            )
            parts.append(f"Rejected: {names}.")
        if clin.uncertainty > 0.3:
            parts.append(f"Clinical context uncertainty {clin.uncertainty:.2f}: {clin.explanation}")
        return " ".join(parts)


__all__ = ["PatientAwareRiskEngine", "ScoredCandidate"]
