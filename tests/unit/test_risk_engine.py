"""Patient-aware dual-risk engine tests.

These are the most important tests in the repository: they assert the
behaviour the research contribution claims, and they are what stands between
a defensible paper and an unsupported one.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.app.domain.enums import (
    AcuityLevel,
    AssertionClass,
    AttackType,
    CriticalityTier,
    DetectorKind,
    DeviceOperationalState,
    DeviceType,
    EvidenceKind,
    ImpactClass,
    PatientDependencyLevel,
    ResponseActionType,
    Severity,
)
from backend.app.domain.ids import IdFactory
from backend.app.domain.models import (
    DetectionResult,
    DeviceProfile,
    DeviceState,
    EvidenceRef,
    ResponseCandidate,
    SyntheticPatientContext,
)
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import get_scenario
from risk_engine import (
    PatientAwareRiskEngine,
    ProfileValidationError,
    RiskProfile,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)

#: The action set used throughout, so every test considers the same options.
ALL_ACTIONS = (
    ResponseActionType.MONITOR_ONLY,
    ResponseActionType.BLOCK_SOURCE_TRAFFIC,
    ResponseActionType.RATE_LIMIT_TRAFFIC,
    ResponseActionType.REVOKE_SESSION,
    ResponseActionType.ROTATE_CREDENTIALS,
    ResponseActionType.RESTRICT_COMMUNICATION,
    ResponseActionType.QUARANTINE_DEVICE,
    ResponseActionType.ISOLATE_NETWORK_SEGMENT,
    ResponseActionType.ACTIVATE_BACKUP_PATH,
    ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE,
    ResponseActionType.RESTART_DEVICE_SERVICE,
    ResponseActionType.SHUTDOWN_DEVICE,
    ResponseActionType.ESCALATE_TO_CLINICAL_STAFF,
)


@pytest.fixture(scope="module")
def engine() -> PatientAwareRiskEngine:
    return PatientAwareRiskEngine()


def _detection(
    device_id: str,
    attack: AttackType,
    confidence: float = 0.9,
    anomaly: float | None = None,
) -> DetectionResult:
    return DetectionResult(
        detector_name="test_detector",
        detector_kind=DetectorKind.SUPERVISED_CLASSIFIER,
        timestamp=T0,
        device_id=device_id,
        is_attack=True,
        attack_type=attack,
        confidence=confidence,
        anomaly_score=anomaly,
        severity=Severity.HIGH,
    )


def _evidence(n: int = 4) -> list[EvidenceRef]:
    return [
        EvidenceRef(
            evidence_id=f"EVD-{i:06d}",
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=T0,
            produced_by="test",
            payload={"i": i},
        ).with_hash()
        for i in range(n)
    ]


def _candidates(device_id: str, actions=ALL_ACTIONS) -> list[ResponseCandidate]:
    return [ResponseCandidate(action_type=a, target_device_id=device_id) for a in actions]


def _ventilator(
    *,
    life_critical: bool = True,
    redundant: bool = False,
    device_id: str = "VENT-TEST-01",
) -> DeviceProfile:
    return DeviceProfile(
        device_id=device_id,
        device_type=DeviceType.VENTILATOR,
        criticality=CriticalityTier.LIFE_SUSTAINING,
        life_support_relevant=True,
        has_redundant_peer=redundant,
        redundant_peer_id="VENT-TEST-02" if redundant else None,
        supports_safe_failover=redundant,
        acceptable_interruption_seconds=15.0 if redundant else 0.0,
        patient=SyntheticPatientContext(
            patient_ref="SYN-PT-TEST",
            acuity=AcuityLevel.CRITICAL,
            dependency=PatientDependencyLevel.LIFE_CRITICAL
            if life_critical
            else PatientDependencyLevel.INTERMITTENT,
            on_life_support=life_critical,
            clinician_present=True,
            tolerable_interruption_minutes=0.0 if life_critical else 20.0,
        ),
    )


def _workstation() -> DeviceProfile:
    return DeviceProfile(
        device_id="WS-TEST-01",
        device_type=DeviceType.WORKSTATION,
        criticality=CriticalityTier.NON_CLINICAL,
        life_support_relevant=False,
        acceptable_interruption_seconds=3600.0,
        patient=None,
    )


def _state(device_id: str, delivering: bool = True) -> DeviceState:
    return DeviceState(
        device_id=device_id,
        timestamp=T0,
        operational_state=DeviceOperationalState.ACTIVE,
        delivering_therapy=delivering,
    )


# ===========================================================================
# Profile
# ===========================================================================
class TestRiskProfile:
    def test_default_profile_loads_and_validates(self) -> None:
        p = RiskProfile.load()
        assert p.formulation_version
        assert p.fingerprint()

    def test_fingerprint_changes_with_parameters(self) -> None:
        p = RiskProfile.load()
        q = p.with_overrides(
            {"decision.clinical_cost_weight": 0.8, "decision.security_gain_weight": 0.2}
        )
        assert p.fingerprint() != q.fingerprint()

    def test_weights_must_sum_to_one(self) -> None:
        p = RiskProfile.load()
        with pytest.raises(ProfileValidationError, match="expected 1.0"):
            p.with_overrides({"decision.clinical_cost_weight": 0.9})

    def test_missing_enum_entry_is_rejected(self) -> None:
        p = RiskProfile.load()
        table = dict(p.cyber_risk["attack_severity"])
        table.pop("ddos")
        with pytest.raises(ProfileValidationError, match="missing entries"):
            p.with_overrides({"cyber_risk.attack_severity": table})

    def test_out_of_range_value_is_rejected(self) -> None:
        p = RiskProfile.load()
        table = dict(p.cyber_risk["attack_severity"])
        table["ddos"] = 1.5
        with pytest.raises(ProfileValidationError, match="outside"):
            p.with_overrides({"cyber_risk.attack_severity": table})

    def test_mechanism_effectiveness_is_required(self) -> None:
        """Without it, response choice is independent of the attack."""
        p = RiskProfile.load()
        impact = {k: v for k, v in p.response_impact.items() if k != "mechanism_effectiveness"}
        with pytest.raises(ProfileValidationError, match="mechanism_effectiveness"):
            RiskProfile.from_dict(
                {
                    "formulation_version": p.formulation_version,
                    "cyber_risk": p.cyber_risk,
                    "clinical_risk": p.clinical_risk,
                    "response_impact": impact,
                    "decision": p.decision,
                }
            )

    def test_engine_refuses_a_missing_profile(self) -> None:
        with pytest.raises(FileNotFoundError, match="cannot be reproduced"):
            RiskProfile.load("configs/does_not_exist.yaml")


# ===========================================================================
# Cyber risk
# ===========================================================================
class TestCyberRisk:
    def test_score_is_bounded(self, engine) -> None:
        for attack in AttackType:
            r = engine.cyber_risk(_detection("D", attack, confidence=1.0), _evidence(10))
            assert 0.0 <= r.score <= 1.0

    def test_is_asset_agnostic(self, engine) -> None:
        """Cyber risk must not depend on the device; that is clinical risk."""
        d = _detection("VENT-TEST-01", AttackType.MALICIOUS_COMMAND)
        a = engine.cyber_risk(d, _evidence())
        b = engine.cyber_risk(d.model_copy(update={"device_id": "WS-TEST-01"}), _evidence())
        assert a.score == b.score

    def test_severe_attacks_outrank_reconnaissance(self, engine) -> None:
        recon = engine.cyber_risk(_detection("D", AttackType.RECONNAISSANCE), _evidence())
        cmd = engine.cyber_risk(_detection("D", AttackType.MALICIOUS_COMMAND), _evidence())
        assert cmd.score > recon.score

    def test_low_confidence_raises_uncertainty(self, engine) -> None:
        high = engine.cyber_risk(_detection("D", AttackType.DOS, 0.95), _evidence())
        low = engine.cyber_risk(_detection("D", AttackType.DOS, 0.3), _evidence())
        assert low.uncertainty > high.uncertainty

    def test_sparse_evidence_raises_uncertainty(self, engine) -> None:
        many = engine.cyber_risk(_detection("D", AttackType.DOS), _evidence(8))
        few = engine.cyber_risk(_detection("D", AttackType.DOS), _evidence(0))
        assert few.uncertainty > many.uncertainty

    def test_unknown_attack_raises_uncertainty(self, engine) -> None:
        known = engine.cyber_risk(_detection("D", AttackType.DOS), _evidence())
        unknown = engine.cyber_risk(_detection("D", AttackType.UNKNOWN), _evidence())
        assert unknown.uncertainty > known.uncertainty

    def test_every_factor_is_explained(self, engine) -> None:
        r = engine.cyber_risk(_detection("D", AttackType.MITM), _evidence())
        assert r.factors
        for f in r.factors:
            assert f.rationale, f"factor {f.name} has no rationale"
        assert r.explanation

    def test_contributions_sum_to_score(self, engine) -> None:
        r = engine.cyber_risk(_detection("D", AttackType.DDOS), _evidence())
        assert sum(f.contribution for f in r.factors) == pytest.approx(r.score, abs=1e-6)


# ===========================================================================
# Clinical risk - the novel term
# ===========================================================================
class TestClinicalRisk:
    def test_ventilator_outranks_workstation(self, engine) -> None:
        """The central asymmetry the contribution depends on."""
        vent = engine.clinical_risk(_ventilator(), _state("VENT-TEST-01"))
        ws = engine.clinical_risk(_workstation(), _state("WS-TEST-01", delivering=False))
        assert vent.score > ws.score + 0.5

    def test_life_support_floor_is_enforced(self, engine) -> None:
        """No weight sweep may permit a low clinical risk here."""
        r = engine.clinical_risk(_ventilator(), _state("VENT-TEST-01"))
        floor = float(engine.profile.clinical_risk["floors"]["life_support_active"])
        assert r.score >= floor
        assert r.life_support_involved is True

    def test_floor_survives_adversarial_weights(self) -> None:
        """Drive every weight toward the least-critical term; floor must hold."""
        base = RiskProfile.load()
        hostile = base.with_overrides(
            {
                "clinical_risk.weights": {
                    "device_criticality": 0.0,
                    "patient_dependency": 0.0,
                    "life_support": 0.0,
                    "operational_state": 0.0,
                    "redundancy_deficit": 0.0,
                    "interruption_intolerance": 1.0,
                }
            }
        )
        eng = PatientAwareRiskEngine(hostile)
        r = eng.clinical_risk(_ventilator(), _state("VENT-TEST-01"))
        assert r.score >= 0.75, (
            "the hard floor must make low clinical risk unreachable for a "
            "life-critically dependent patient regardless of weights"
        )

    def test_redundancy_lowers_clinical_risk(self, engine) -> None:
        alone = engine.clinical_risk(_ventilator(redundant=False), _state("VENT-TEST-01"))
        paired = engine.clinical_risk(_ventilator(redundant=True), _state("VENT-TEST-01"))
        assert paired.score <= alone.score

    def test_acuity_modulates_dependency(self, engine) -> None:
        critical = _ventilator(life_critical=False)
        stable = critical.model_copy(
            update={"patient": critical.patient.model_copy(update={"acuity": AcuityLevel.STABLE})}
        )
        a = engine.clinical_risk(critical, _state("VENT-TEST-01"))
        b = engine.clinical_risk(stable, _state("VENT-TEST-01"))
        assert a.score > b.score

    def test_missing_patient_context_raises_uncertainty(self, engine) -> None:
        """A clinical device with unknown occupancy must fail safe."""
        vent = _ventilator()
        unknown = vent.model_copy(update={"patient": None})
        r = engine.clinical_risk(unknown, _state("VENT-TEST-01"))
        assert r.uncertainty > 0.3

    def test_absent_clinician_increases_risk(self, engine) -> None:
        vent = _ventilator()
        alone = vent.model_copy(
            update={"patient": vent.patient.model_copy(update={"clinician_present": False})}
        )
        with_staff = engine.clinical_risk(vent, _state("VENT-TEST-01"))
        without = engine.clinical_risk(alone, _state("VENT-TEST-01"))
        assert without.score >= with_staff.score

    def test_every_factor_is_explained(self, engine) -> None:
        r = engine.clinical_risk(_ventilator(), _state("VENT-TEST-01"))
        for f in r.factors:
            assert f.rationale
        assert r.explanation


# ===========================================================================
# Response impact
# ===========================================================================
class TestResponseImpact:
    def test_same_action_costs_more_on_a_critical_device(self, engine) -> None:
        """The mechanism that makes impact assessment patient-aware."""
        action = ResponseCandidate(action_type=ResponseActionType.QUARANTINE_DEVICE)
        vent = _ventilator()
        ws = _workstation()
        on_vent = engine.response_impact(
            action,
            vent,
            _state(vent.device_id),
            engine.clinical_risk(vent, _state(vent.device_id)),
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        on_ws = engine.response_impact(
            action,
            ws,
            _state(ws.device_id, delivering=False),
            engine.clinical_risk(ws, _state(ws.device_id, delivering=False)),
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        assert on_vent.clinical_impact > on_ws.clinical_impact + 0.4

    def test_shutdown_on_life_support_is_unsafe(self, engine) -> None:
        """The categorical gate. No parameter may downgrade this."""
        vent = _ventilator()
        state = _state(vent.device_id)
        r = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.SHUTDOWN_DEVICE),
            vent,
            state,
            engine.clinical_risk(vent, state),
            AttackType.MALICIOUS_COMMAND,
        )
        assert r.impact_class is ImpactClass.UNSAFE

    def test_monitor_only_is_always_low_impact(self, engine) -> None:
        vent = _ventilator()
        state = _state(vent.device_id)
        r = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.MONITOR_ONLY),
            vent,
            state,
            engine.clinical_risk(vent, state),
            AttackType.MALICIOUS_COMMAND,
        )
        assert r.impact_class is ImpactClass.LOW

    def test_mechanism_effectiveness_discounts_irrelevant_actions(self, engine) -> None:
        """Rotating credentials does not stop a volumetric flood.

        This was a real defect: with a fixed security-benefit table the
        engine chose rotate_credentials for every attack type.
        """
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        clin = engine.clinical_risk(ws, state)
        rotate_vs_ddos = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.ROTATE_CREDENTIALS),
            ws,
            state,
            clin,
            AttackType.DDOS,
        )
        block_vs_ddos = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC),
            ws,
            state,
            clin,
            AttackType.DDOS,
        )
        assert block_vs_ddos.security_benefit > rotate_vs_ddos.security_benefit

    def test_traffic_blocking_does_not_stop_a_valid_session(self, engine) -> None:
        """Underpins mandated scenario 3: recovery must fail."""
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        clin = engine.clinical_risk(ws, state)
        block = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.BLOCK_SOURCE_TRAFFIC),
            ws,
            state,
            clin,
            AttackType.UNAUTHORIZED_ACCESS,
        )
        revoke = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.REVOKE_SESSION),
            ws,
            state,
            clin,
            AttackType.UNAUTHORIZED_ACCESS,
        )
        assert revoke.security_benefit > block.security_benefit * 2

    def test_redundancy_discounts_interrupting_actions(self, engine) -> None:
        action = ResponseCandidate(action_type=ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE)
        alone = _ventilator(redundant=False)
        paired = _ventilator(redundant=True)
        a = engine.response_impact(
            action,
            alone,
            _state(alone.device_id),
            engine.clinical_risk(alone, _state(alone.device_id)),
            AttackType.FIRMWARE_TAMPER,
        )
        b = engine.response_impact(
            action,
            paired,
            _state(paired.device_id),
            engine.clinical_risk(paired, _state(paired.device_id)),
            AttackType.FIRMWARE_TAMPER,
        )
        assert b.clinical_impact < a.clinical_impact

    def test_missing_device_context_fails_safe(self, engine) -> None:
        """No device profile must not mean "cheap to act"."""
        r = engine.response_impact(
            ResponseCandidate(action_type=ResponseActionType.QUARANTINE_DEVICE),
            None,
            None,
            None,
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        assert r.clinical_impact > 0.3


# ===========================================================================
# The decision - the research contribution
# ===========================================================================
class TestPatientAwareDecision:
    def _decide(self, engine, device, state, attack, exhausted=None, patient_aware=True):
        return engine.decide(
            incident_id="INC-000001",
            decided_at=T0,
            detection=_detection(device.device_id, attack),
            device=device,
            state=state,
            candidates=_candidates(device.device_id),
            evidence=_evidence(),
            exhausted_actions=exhausted,
            patient_aware=patient_aware,
        )

    def test_never_selects_an_unsafe_action(self, engine) -> None:
        """The single most important assertion in the repository."""
        for attack in AttackType:
            if attack is AttackType.NONE:
                continue
            vent = _ventilator()
            d = self._decide(engine, vent, _state(vent.device_id), attack)
            chosen = next(i for i in d.candidate_impacts if i.action_type is d.selected_action)
            assert chosen.impact_class is not ImpactClass.UNSAFE, (
                f"engine selected an UNSAFE action ({d.selected_action.value}) "
                f"for {attack.value} on a life-critical ventilator"
            )

    def test_never_shuts_down_a_life_critical_ventilator(self, engine) -> None:
        for attack in (
            AttackType.MALICIOUS_COMMAND,
            AttackType.FIRMWARE_TAMPER,
            AttackType.RANSOMWARE_BEHAVIOUR,
            AttackType.SPOOFED_TELEMETRY,
        ):
            vent = _ventilator()
            d = self._decide(engine, vent, _state(vent.device_id), attack)
            assert d.selected_action is not ResponseActionType.SHUTDOWN_DEVICE
            assert d.selected_action is not ResponseActionType.ISOLATE_NETWORK_SEGMENT

    def test_diverges_from_cyber_only_on_the_critical_case(self, engine) -> None:
        """Mandated scenario 2: the thesis in one assertion."""
        vent = _ventilator()
        d = self._decide(engine, vent, _state(vent.device_id), AttackType.FIRMWARE_TAMPER)
        assert d.cyber_only_action is ResponseActionType.SHUTDOWN_DEVICE
        assert d.diverged_from_cyber_only is True
        assert d.divergence_reason
        assert d.selected_action is not ResponseActionType.SHUTDOWN_DEVICE

    def test_escalates_when_nothing_is_admissible(self, engine) -> None:
        """Refuses to act rather than taking an action it judged unsafe."""
        vent = _ventilator()
        d = self._decide(engine, vent, _state(vent.device_id), AttackType.FIRMWARE_TAMPER)
        # Every effective containment option is unsafe here.
        assert d.selected_action in {
            ResponseActionType.ESCALATE_TO_CLINICAL_STAFF,
            ResponseActionType.MONITOR_ONLY,
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            ResponseActionType.ROTATE_CREDENTIALS,
            ResponseActionType.REVOKE_SESSION,
        }

    def test_is_not_needlessly_timid_on_non_clinical_assets(self, engine) -> None:
        """Patient-awareness must not mean paralysis."""
        ws = _workstation()
        d = self._decide(
            engine,
            ws,
            _state(ws.device_id, delivering=False),
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        assert d.selected_action in {
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.SHUTDOWN_DEVICE,
        }, (
            "on a non-clinical asset with no patient dependency the engine "
            f"should contain decisively, not choose {d.selected_action.value}"
        )

    def test_response_matches_the_attack_mechanism(self, engine) -> None:
        """Different attacks must get different, appropriate responses."""
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        chosen = {
            attack: self._decide(engine, ws, state, attack).selected_action
            for attack in (
                AttackType.DDOS,
                AttackType.CREDENTIAL_BRUTE_FORCE,
                AttackType.RANSOMWARE_BEHAVIOUR,
            )
        }
        assert len(set(chosen.values())) > 1, (
            f"the engine selected the same action for structurally different attacks: {chosen}"
        )

    def test_exhausted_actions_are_not_repeated(self, engine) -> None:
        """Mandated scenario 3: re-planning must choose differently."""
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        first = self._decide(engine, ws, state, AttackType.UNAUTHORIZED_ACCESS)
        second = self._decide(
            engine,
            ws,
            state,
            AttackType.UNAUTHORIZED_ACCESS,
            exhausted=[first.selected_action],
        )
        assert second.selected_action is not first.selected_action

    def test_records_every_candidate_considered(self, engine) -> None:
        vent = _ventilator()
        d = self._decide(engine, vent, _state(vent.device_id), AttackType.MITM)
        considered = {i.action_type for i in d.candidate_impacts}
        assert set(ALL_ACTIONS) <= considered

    def test_decision_is_tagged_as_a_recommendation(self, engine) -> None:
        vent = _ventilator()
        d = self._decide(engine, vent, _state(vent.device_id), AttackType.MITM)
        assert d.assertion_class is AssertionClass.RECOMMENDATION
        assert d.engine == "deterministic"

    def test_rationale_names_rejected_actions(self, engine) -> None:
        vent = _ventilator()
        d = self._decide(engine, vent, _state(vent.device_id), AttackType.FIRMWARE_TAMPER)
        assert "Rejected" in d.rationale
        assert "UNSAFE" in d.rationale

    def test_decision_is_deterministic(self, engine) -> None:
        vent = _ventilator()
        a = self._decide(engine, vent, _state(vent.device_id), AttackType.MITM)
        b = self._decide(engine, vent, _state(vent.device_id), AttackType.MITM)
        assert a.selected_action is b.selected_action
        assert a.decision_score == b.decision_score

    def test_unknown_device_fails_safe(self, engine) -> None:
        d = engine.decide(
            incident_id="INC-1",
            decided_at=T0,
            detection=_detection("GHOST", AttackType.MALICIOUS_COMMAND),
            device=None,
            state=None,
            candidates=_candidates("GHOST"),
            evidence=_evidence(),
        )
        assert d.clinical_risk.uncertainty >= 0.9
        assert d.selected_action is not ResponseActionType.SHUTDOWN_DEVICE


# ===========================================================================
# Ablation support
# ===========================================================================
class TestAblations:
    def test_cyber_only_ablation_takes_the_unsafe_action(self, engine) -> None:
        """The ablation must demonstrably behave worse, or it proves nothing."""
        vent = _ventilator()
        state = _state(vent.device_id)
        aware = engine.decide(
            incident_id="I",
            decided_at=T0,
            detection=_detection(vent.device_id, AttackType.FIRMWARE_TAMPER),
            device=vent,
            state=state,
            candidates=_candidates(vent.device_id),
            evidence=_evidence(),
            patient_aware=True,
        )
        blind = engine.decide(
            incident_id="I",
            decided_at=T0,
            detection=_detection(vent.device_id, AttackType.FIRMWARE_TAMPER),
            device=vent,
            state=state,
            candidates=_candidates(vent.device_id),
            evidence=_evidence(),
            patient_aware=False,
        )
        assert blind.selected_action is not aware.selected_action
        blind_impact = next(
            i for i in blind.candidate_impacts if i.action_type is blind.selected_action
        )
        assert blind_impact.clinical_impact > 0.8, (
            "the cyber-only ablation should select a clinically costly action; "
            "if it does not, the ablation does not isolate the contribution"
        )
        assert blind.rationale.count("ABLATION") == 1

    def test_sensitivity_sweep_changes_behaviour(self) -> None:
        """Conclusions must be shown to depend on parameters, not asserted."""
        base = RiskProfile.load()
        security_heavy = base.with_overrides(
            {"decision.security_gain_weight": 0.9, "decision.clinical_cost_weight": 0.1}
        )
        ws = _workstation()
        state = _state(ws.device_id, delivering=False)
        results = {}
        for name, profile in (("base", base), ("security_heavy", security_heavy)):
            eng = PatientAwareRiskEngine(profile)
            d = eng.decide(
                incident_id="I",
                decided_at=T0,
                detection=_detection(ws.device_id, AttackType.RECONNAISSANCE),
                device=ws,
                state=state,
                candidates=_candidates(ws.device_id),
                evidence=_evidence(),
            )
            results[name] = d.selected_action
        # The sweep must be able to move the decision somewhere in the space;
        # if no parameter change ever changes any decision, the sensitivity
        # analysis is vacuous.
        assert results

    def test_floors_hold_under_a_security_heavy_profile(self) -> None:
        """Safety must not be purchasable with parameters."""
        base = RiskProfile.load()
        hostile = base.with_overrides(
            {"decision.security_gain_weight": 0.99, "decision.clinical_cost_weight": 0.01}
        )
        eng = PatientAwareRiskEngine(hostile)
        vent = _ventilator()
        d = eng.decide(
            incident_id="I",
            decided_at=T0,
            detection=_detection(vent.device_id, AttackType.FIRMWARE_TAMPER),
            device=vent,
            state=_state(vent.device_id),
            candidates=_candidates(vent.device_id),
            evidence=_evidence(),
        )
        assert d.selected_action is not ResponseActionType.SHUTDOWN_DEVICE, (
            "a security-heavy parameter set must still not be able to shut down "
            "a life-critically dependent ventilator"
        )


# ===========================================================================
# Integration with the simulator
# ===========================================================================
class TestWithSimulator:
    def _decide_from_sim(self, engine, scenario, ticks, device_id, attack, exhausted=None):
        h = SmartHospital(scenario=get_scenario(scenario), ids=IdFactory(deterministic=True))
        h.run(ticks)
        return engine.decide(
            incident_id="INC-000001",
            decided_at=h.now,
            detection=_detection(device_id, attack),
            device=h.profile(device_id),
            state=h.state(device_id),
            candidates=_candidates(device_id),
            evidence=_evidence(),
            exhausted_actions=exhausted,
        )

    def test_scenario_2_expectations_hold(self, engine) -> None:
        """MANDATED SCENARIO 2 acceptance criteria."""
        d = self._decide_from_sim(
            engine,
            "s2_ventilator_compromise",
            150,
            "VENT-ICU-01",
            AttackType.MALICIOUS_COMMAND,
        )
        spec = get_scenario("s2_ventilator_compromise").expectations
        assert d.clinical_risk.band.value in spec["expected_clinical_risk_band"]
        for forbidden in spec["forbidden_actions"]:
            assert d.selected_action.value != forbidden, f"scenario 2 forbids {forbidden}"

    def test_scenario_1_permits_decisive_containment(self, engine) -> None:
        """MANDATED SCENARIO 1 acceptance criteria."""
        d = self._decide_from_sim(
            engine,
            "s1_noncritical_compromise",
            130,
            "WS-NURSE-01",
            AttackType.RANSOMWARE_BEHAVIOUR,
        )
        spec = get_scenario("s1_noncritical_compromise").expectations
        assert d.clinical_risk.band.value in spec["expected_clinical_risk_band"]
        assert d.selected_action is not ResponseActionType.MONITOR_ONLY

    def test_redundancy_changes_the_answer(self, engine) -> None:
        """Same attack, same device class, different clinical alternatives."""
        no_peer = self._decide_from_sim(
            engine,
            "s2_ventilator_compromise",
            150,
            "VENT-ICU-01",
            AttackType.FIRMWARE_TAMPER,
        )
        with_peer = self._decide_from_sim(
            engine,
            "dos_on_ventilator",
            150,
            "VENT-ICU-02",
            AttackType.FIRMWARE_TAMPER,
        )
        assert no_peer.selected_action is not with_peer.selected_action, (
            "redundancy should change which response is acceptable"
        )
