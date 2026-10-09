"""Recovery verification engine.

Determines whether an executed response actually worked — and whether it
broke something. Recovery is mandatory: the incident lifecycle makes
``RESOLVED`` reachable only through ``RECOVERING``, so execution alone
cannot close an incident.

The checks are deterministic observations of post-response device, network
and detector state. Four of them matter in ways worth stating:

``anomaly_cleared``
    The triggering condition is gone. Not "an action was executed" —
    execution is not recovery, and conflating the two is how a platform
    closes an incident while the attacker is still present.

``no_new_fault_introduced``
    The response did not itself break the device. A containment action that
    stops the attack and interrupts therapy has not succeeded; this is the
    check that makes that explicit rather than leaving it to judgement.

``therapy_continuity``
    For a device delivering therapy to a dependent patient, therapy is
    still being delivered. This check is why the recovery engine is part of
    the patient-aware contribution and not generic incident closure.

``attack_mechanism_severed``
    The specific mechanism the attack depended on is no longer available.
    This is what makes mandated scenario 3 principled: blocking traffic
    does not revoke a valid session, so the check fails and the loop
    re-plans with a different action rather than declaring victory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    DeviceOperationalState,
    PatientDependencyLevel,
    RecoveryOutcome,
    ResponseActionType,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    DeviceProfile,
    DeviceState,
    RecoveryCheck,
    RecoveryResult,
    ResponseRecord,
    RiskFactor,
)

#: Which response actions sever which attack mechanisms. The complement of
#: this mapping is what makes a "successful" execution still fail recovery:
#: an action that does not appear here for the attack in question did not
#: remove the attacker's capability, however cleanly it executed.
MECHANISM_SEVERED_BY: dict[AttackType, frozenset[ResponseActionType]] = {
    AttackType.DOS: frozenset(
        {
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            ResponseActionType.RATE_LIMIT_TRAFFIC,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.ACTIVATE_BACKUP_PATH,
        }
    ),
    AttackType.DDOS: frozenset(
        {
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            ResponseActionType.RATE_LIMIT_TRAFFIC,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.ACTIVATE_BACKUP_PATH,
        }
    ),
    AttackType.RECONNAISSANCE: frozenset(
        {
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            ResponseActionType.RESTRICT_COMMUNICATION,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
        }
    ),
    AttackType.PORT_SCAN: frozenset(
        {
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
            ResponseActionType.RESTRICT_COMMUNICATION,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
        }
    ),
    AttackType.ARP_SPOOFING: frozenset(
        {
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.RESTRICT_COMMUNICATION,
        }
    ),
    AttackType.MITM: frozenset(
        {
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.RESTRICT_COMMUNICATION,
        }
    ),
    AttackType.CREDENTIAL_BRUTE_FORCE: frozenset(
        {
            ResponseActionType.ROTATE_CREDENTIALS,
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.BLOCK_SOURCE_TRAFFIC,
        }
    ),
    # THE KEY ASYMMETRY. An attacker holding a valid session is not removed
    # by blocking their traffic: they already have the session. Only
    # revoking it or rotating credentials severs this mechanism. Mandated
    # scenario 3 depends on this being modelled honestly.
    AttackType.UNAUTHORIZED_ACCESS: frozenset(
        {
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.ROTATE_CREDENTIALS,
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
        }
    ),
    AttackType.MALICIOUS_COMMAND: frozenset(
        {
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.ROTATE_CREDENTIALS,
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
        }
    ),
    AttackType.SPOOFED_TELEMETRY: frozenset(
        {
            ResponseActionType.ROTATE_CREDENTIALS,
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.QUARANTINE_DEVICE,
        }
    ),
    AttackType.FIRMWARE_TAMPER: frozenset(
        {
            ResponseActionType.SHUTDOWN_DEVICE,
            ResponseActionType.FAILOVER_TO_REDUNDANT_DEVICE,
            ResponseActionType.QUARANTINE_DEVICE,
        }
    ),
    AttackType.RANSOMWARE_BEHAVIOUR: frozenset(
        {
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.ISOLATE_NETWORK_SEGMENT,
            ResponseActionType.SHUTDOWN_DEVICE,
        }
    ),
}


@dataclass
class RecoveryObservation:
    """Post-response observations the engine checks against.

    Supplied by the orchestrator from the simulator and detector, not
    gathered by this module, so the engine stays a pure function of
    observed state and is trivially testable.
    """

    device_state: DeviceState | None
    device_profile: DeviceProfile | None
    #: Whether the detector still flags the device after the response.
    detector_still_flagging: bool
    #: Attack types the simulator still has installed on the device. Ground
    #: truth, used ONLY to compute the honest mechanism check in simulation;
    #: a deployed system would infer this from telemetry.
    active_attack_types: frozenset[AttackType] = frozenset()
    #: Network flow rate after the response, for containment checking.
    post_response_flow_rate: float | None = None
    #: Baseline flow rate for comparison.
    baseline_flow_rate: float | None = None
    #: Device state captured before the response, to detect new faults.
    pre_response_state: DeviceState | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoveryConfig:
    """Thresholds. Swept in the sensitivity analysis."""

    #: Flow rate above this multiple of baseline counts as uncontained.
    flow_containment_multiple: float = 2.5
    #: Residual risk at or above this requires re-investigation.
    residual_risk_threshold: float = 0.35
    #: Checks that must pass for RECOVERED. Failing any of these cannot be
    #: offset by passing the others.
    mandatory_checks: tuple[str, ...] = (
        "anomaly_cleared",
        "attack_mechanism_severed",
        "no_new_fault_introduced",
        "therapy_continuity",
    )


class RecoveryEngine:
    """Deterministic recovery verification."""

    def __init__(
        self,
        ids: IdFactory,
        clock: Clock,
        config: RecoveryConfig | None = None,
    ) -> None:
        self.ids = ids
        self.clock = clock
        self.config = config or RecoveryConfig()

    def verify(
        self,
        incident_id: str,
        response: ResponseRecord,
        observation: RecoveryObservation,
        attack_type: AttackType,
        exhausted_actions: list[ResponseActionType] | None = None,
    ) -> RecoveryResult:
        checks: list[RecoveryCheck] = [
            self._check_execution(response),
            self._check_anomaly_cleared(observation),
            self._check_mechanism_severed(response, observation, attack_type),
            self._check_device_available(observation),
            self._check_network_contained(observation),
            self._check_no_new_fault(observation),
            self._check_therapy_continuity(observation),
        ]

        failed = [c for c in checks if not c.passed]
        mandatory_failed = [c for c in failed if c.name in self.config.mandatory_checks]

        residual, factors = self._residual_risk(checks, observation, attack_type)

        new_fault = not next(c.passed for c in checks if c.name == "no_new_fault_introduced")
        if new_fault:
            outcome = RecoveryOutcome.NEW_FAULT_INTRODUCED
        elif not response.execution_succeeded:
            outcome = RecoveryOutcome.FAILED
        elif mandatory_failed:
            outcome = RecoveryOutcome.RESIDUAL_RISK if residual < 0.75 else RecoveryOutcome.FAILED
        elif residual >= self.config.residual_risk_threshold:
            outcome = RecoveryOutcome.RESIDUAL_RISK
        else:
            outcome = RecoveryOutcome.RECOVERED

        requires_reinvestigation = outcome is not RecoveryOutcome.RECOVERED

        already = list(exhausted_actions or [])
        if response.candidate.action_type not in already and requires_reinvestigation:
            already.append(response.candidate.action_type)

        explanation = self._explain(response, checks, failed, outcome, residual, attack_type)

        return RecoveryResult(
            recovery_id=self.ids.recovery(),
            incident_id=incident_id,
            response_id=response.response_id,
            verified_at=self.clock.now(),
            outcome=outcome,
            checks=checks,
            residual_risk=round(residual, 6),
            residual_factors=factors,
            requires_reinvestigation=requires_reinvestigation,
            explanation=explanation,
            exhausted_actions=already,
        )

    # -- individual checks -------------------------------------------------
    @staticmethod
    def _check_execution(response: ResponseRecord) -> RecoveryCheck:
        ok = bool(response.execution_succeeded)
        return RecoveryCheck(
            name="response_executed",
            passed=ok,
            observed=response.execution_detail or ("executed" if ok else "not executed"),
            expected="the response executed without actuator error",
        )

    @staticmethod
    def _check_anomaly_cleared(obs: RecoveryObservation) -> RecoveryCheck:
        """Execution is not recovery: the triggering condition must be gone."""
        still = obs.detector_still_flagging
        return RecoveryCheck(
            name="anomaly_cleared",
            passed=not still,
            observed=(
                "detector still flags this device"
                if still
                else "detector no longer flags this device"
            ),
            expected="the triggering anomaly is no longer detected",
        )

    def _check_mechanism_severed(
        self,
        response: ResponseRecord,
        obs: RecoveryObservation,
        attack_type: AttackType,
    ) -> RecoveryCheck:
        """Did the response remove the attacker's actual capability?"""
        action = response.candidate.action_type
        effective = MECHANISM_SEVERED_BY.get(attack_type, frozenset())
        action_addresses = action in effective
        still_active = attack_type in obs.active_attack_types

        passed = action_addresses and not still_active
        if not action_addresses:
            observed = f"{action.value} does not sever the mechanism {attack_type.value} depends on"
        elif still_active:
            observed = (
                f"{action.value} addresses {attack_type.value} but the attack "
                "is still active against this device"
            )
        else:
            observed = f"{action.value} severed the {attack_type.value} mechanism"
        return RecoveryCheck(
            name="attack_mechanism_severed",
            passed=passed,
            observed=observed,
            expected=(
                f"an action in {sorted(a.value for a in effective)} and no "
                "remaining attack activity"
            ),
        )

    @staticmethod
    def _check_device_available(obs: RecoveryObservation) -> RecoveryCheck:
        state = obs.device_state
        if state is None:
            return RecoveryCheck(
                name="device_service_available",
                passed=False,
                observed="device state unavailable",
                expected="device state observable and service available",
            )
        ok = state.service_available and state.operational_state not in {
            DeviceOperationalState.OFFLINE,
            DeviceOperationalState.FAULT,
        }
        return RecoveryCheck(
            name="device_service_available",
            passed=ok,
            observed=(
                f"operational_state={state.operational_state.value}, "
                f"service_available={state.service_available}"
            ),
            expected="device reachable and its service available",
        )

    def _check_network_contained(self, obs: RecoveryObservation) -> RecoveryCheck:
        if obs.post_response_flow_rate is None or obs.baseline_flow_rate is None:
            return RecoveryCheck(
                name="network_contained",
                passed=True,
                observed="no flow measurement available; check not applicable",
                expected="post-response flow rate near baseline",
            )
        ceiling = obs.baseline_flow_rate * self.config.flow_containment_multiple
        ok = obs.post_response_flow_rate <= ceiling
        return RecoveryCheck(
            name="network_contained",
            passed=ok,
            observed=(
                f"{obs.post_response_flow_rate:.0f} pps against baseline "
                f"{obs.baseline_flow_rate:.0f} pps"
            ),
            expected=f"at most {ceiling:.0f} pps",
        )

    @staticmethod
    def _check_no_new_fault(obs: RecoveryObservation) -> RecoveryCheck:
        """Did the response itself break the device?"""
        state, before = obs.device_state, obs.pre_response_state
        if state is None:
            return RecoveryCheck(
                name="no_new_fault_introduced",
                passed=False,
                observed="device state unavailable",
                expected="no fault codes absent before the response",
            )
        prior = set(before.fault_codes) if before else set()
        new = sorted(set(state.fault_codes) - prior)

        lost_therapy = bool(
            before
            and before.delivering_therapy
            and not state.delivering_therapy
            and obs.device_profile
            and obs.device_profile.patient
            and obs.device_profile.patient.dependency
            in {PatientDependencyLevel.CONTINUOUS, PatientDependencyLevel.LIFE_CRITICAL}
        )

        passed = not new and not lost_therapy
        parts = []
        if new:
            parts.append(f"new fault codes {new}")
        if lost_therapy:
            parts.append(
                "therapy delivery stopped for a dependent patient as a result of the response"
            )
        return RecoveryCheck(
            name="no_new_fault_introduced",
            passed=passed,
            observed="; ".join(parts) if parts else "no new fault introduced",
            expected="the response introduced no new fault and did not stop therapy",
        )

    @staticmethod
    def _check_therapy_continuity(obs: RecoveryObservation) -> RecoveryCheck:
        """Therapy must still reach a patient who depends on it."""
        state, profile = obs.device_state, obs.device_profile
        if state is None or profile is None or profile.patient is None:
            return RecoveryCheck(
                name="therapy_continuity",
                passed=True,
                observed="no dependent patient on this device; not applicable",
                expected="therapy continues for a dependent patient",
            )
        dependency = profile.patient.dependency
        if dependency in {PatientDependencyLevel.NONE, PatientDependencyLevel.INTERMITTENT}:
            return RecoveryCheck(
                name="therapy_continuity",
                passed=True,
                observed=f"patient dependency is {dependency.value}; not applicable",
                expected="therapy continues for a dependent patient",
            )
        ok = state.delivering_therapy
        return RecoveryCheck(
            name="therapy_continuity",
            passed=ok,
            observed=(
                f"delivering_therapy={state.delivering_therapy} with patient "
                f"dependency {dependency.value}"
            ),
            expected="therapy continuing for a continuously dependent patient",
        )

    # -- residual risk -----------------------------------------------------
    def _residual_risk(
        self,
        checks: list[RecoveryCheck],
        obs: RecoveryObservation,
        attack_type: AttackType,
    ) -> tuple[float, list[RiskFactor]]:
        """Residual risk from the specific checks that failed.

        Weighted rather than a simple failure fraction, because the checks
        are not equally informative: a still-active attack mechanism is far
        more serious than a missing flow measurement.
        """
        weights = {
            "response_executed": 0.15,
            "anomaly_cleared": 0.20,
            "attack_mechanism_severed": 0.30,
            "device_service_available": 0.10,
            "network_contained": 0.10,
            "no_new_fault_introduced": 0.10,
            "therapy_continuity": 0.05,
        }
        factors: list[RiskFactor] = []
        total = 0.0
        for check in checks:
            weight = weights.get(check.name, 0.05)
            value = 0.0 if check.passed else 1.0
            contribution = weight * value
            total += contribution
            if not check.passed:
                factors.append(
                    RiskFactor(
                        name=f"failed_{check.name}",
                        value=value,
                        weight=weight,
                        contribution=contribution,
                        rationale=check.observed,
                        assertion_class=AssertionClass.OBSERVED_FACT,
                    )
                )
        if attack_type in obs.active_attack_types:
            # A still-active attack is decisive regardless of what passed.
            total = max(total, 0.6)
            factors.append(
                RiskFactor(
                    name="attack_still_active",
                    value=1.0,
                    weight=0.6,
                    contribution=0.6,
                    rationale=(
                        f"{attack_type.value} remains active against this device after the response"
                    ),
                    assertion_class=AssertionClass.OBSERVED_FACT,
                )
            )
        return max(0.0, min(1.0, total)), factors

    @staticmethod
    def _explain(
        response: ResponseRecord,
        checks: list[RecoveryCheck],
        failed: list[RecoveryCheck],
        outcome: RecoveryOutcome,
        residual: float,
        attack_type: AttackType,
    ) -> str:
        passed = len(checks) - len(failed)
        parts = [
            f"{response.candidate.action_type.value} against "
            f"{attack_type.value}: {passed}/{len(checks)} checks passed, "
            f"residual risk {residual:.2f}, outcome {outcome.value}."
        ]
        if failed:
            parts.append("Failed: " + "; ".join(f"{c.name} ({c.observed})" for c in failed) + ".")
        if outcome is RecoveryOutcome.NEW_FAULT_INTRODUCED:
            parts.append(
                "The response introduced a new fault. Containment that harms "
                "the device has not succeeded."
            )
        elif outcome is not RecoveryOutcome.RECOVERED:
            parts.append(
                "Re-investigation required; re-planning must select a "
                f"different action than {response.candidate.action_type.value}."
            )
        return " ".join(parts)


__all__ = [
    "MECHANISM_SEVERED_BY",
    "RecoveryConfig",
    "RecoveryEngine",
    "RecoveryObservation",
]
