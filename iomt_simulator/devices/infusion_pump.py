"""Simulated infusion pump.

Models medication delivery as a reservoir draining at a commanded rate,
with occlusion pressure as the primary safety signal. The clinically
meaningful attack surface is the *commanded rate*: a malicious command that
raises the rate produces a correct-looking but dangerous device.
"""

from __future__ import annotations

from datetime import datetime

from backend.app.domain.enums import (
    AttackType,
    DeviceOperationalState,
    DeviceType,
    EventKind,
)
from backend.app.domain.models import NormalisedEvent
from iomt_simulator.base import SimulatedDevice


class InfusionPump(SimulatedDevice):
    """Volumetric infusion pump with occlusion and reservoir modelling."""

    device_type = DeviceType.INFUSION_PUMP

    # Clinically plausible envelope for the simulated medication (mL/h).
    PRESCRIBED_RATE_ML_H = 25.0
    MAX_SAFE_RATE_ML_H = 60.0
    RESERVOIR_ML = 250.0

    def initialise(self) -> None:
        self.commanded_rate = self.PRESCRIBED_RATE_ML_H
        self.actual_rate = self.PRESCRIBED_RATE_ML_H
        self.reservoir_ml = self.RESERVOIR_ML
        self.occlusion_pressure_mmhg = 120.0
        self.total_delivered_ml = 0.0
        self.state.delivering_therapy = True
        self.state.operational_state = DeviceOperationalState.ACTIVE
        self._command_seq = 0
        self._rate_tampered = False

    # -- physiology --------------------------------------------------------
    def advance_physiology(self, now: datetime) -> None:
        attacks = self.active_attacks(now)
        self._rate_tampered = False

        # A malicious command raises the commanded rate. This is the
        # dangerous case: the pump reports healthy operation at a harmful
        # rate, so detection must come from command/auth context, not from
        # the pump declaring a fault.
        for a in attacks:
            if a.attack_type == AttackType.MALICIOUS_COMMAND:
                target = a.params.get("target_rate_ml_h", self.MAX_SAFE_RATE_ML_H * 1.8)
                self.commanded_rate = target
                self._rate_tampered = True
            elif a.attack_type == AttackType.FIRMWARE_TAMPER:
                # Firmware tamper decouples actual from commanded delivery.
                self._rate_tampered = True

        if not self._rate_tampered:
            # Drift gently back toward prescription after remediation.
            self.commanded_rate += (self.PRESCRIBED_RATE_ML_H - self.commanded_rate) * 0.25

        if self.state.operational_state in {
            DeviceOperationalState.OFFLINE,
            DeviceOperationalState.QUARANTINED,
            DeviceOperationalState.ISOLATED,
        } and self.has_control("shutdown_device"):
            self.actual_rate = 0.0
            self.state.delivering_therapy = False
        else:
            self.actual_rate = max(0.0, self.commanded_rate + self.jitter(0.35))
            self.state.delivering_therapy = self.actual_rate > 0.5

        delivered = self.actual_rate * (self.tick_seconds / 3600.0)
        self.reservoir_ml = max(0.0, self.reservoir_ml - delivered)
        self.total_delivered_ml += delivered

        # Occlusion pressure rises with flow rate; this is a real safety
        # interlock on physical pumps and a useful anomaly signal here.
        target_pressure = 110.0 + 2.1 * self.actual_rate
        self.occlusion_pressure_mmhg += (
            target_pressure - self.occlusion_pressure_mmhg
        ) * 0.3 + self.jitter(1.2)

        over_rate = self.actual_rate > self.MAX_SAFE_RATE_ML_H
        empty = self.reservoir_ml <= 1.0
        high_pressure = self.occlusion_pressure_mmhg > 280.0

        self.state.alarm_active = bool(over_rate or empty or high_pressure)
        if over_rate:
            self.state.alarm_reason = "rate_above_safe_limit"
        elif empty:
            self.state.alarm_reason = "reservoir_empty"
        elif high_pressure:
            self.state.alarm_reason = "occlusion_pressure_high"
        else:
            self.state.alarm_reason = None

        active = self.state.operational_state == DeviceOperationalState.ACTIVE
        if self.state.alarm_active and active:
            self.state.operational_state = DeviceOperationalState.ALARM
        elif (
            not self.state.alarm_active
            and self.state.operational_state == DeviceOperationalState.ALARM
        ):
            self.state.operational_state = DeviceOperationalState.ACTIVE

    # -- telemetry ---------------------------------------------------------
    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.TELEMETRY,
            device_id=self.profile.device_id,
            source_ip=self.profile.ip_address,
            source_mac=self.profile.mac_address,
            protocol="mqtt",
            measurements={
                "commanded_rate_ml_h": round(self.commanded_rate, 4),
                "actual_rate_ml_h": round(self.actual_rate, 4),
                "reservoir_ml": round(self.reservoir_ml, 4),
                "occlusion_pressure_mmhg": round(self.occlusion_pressure_mmhg, 4),
                "total_delivered_ml": round(self.total_delivered_ml, 4),
                "battery_pct": round(max(0.0, 100.0 - self.state.uptime_seconds / 600.0), 3),
            },
            attributes={
                "device_type": self.device_type.value,
                "alarm": str(self.state.alarm_active).lower(),
                "alarm_reason": self.state.alarm_reason or "",
                "therapy_active": str(self.state.delivering_therapy).lower(),
            },
        )

    # -- commands ----------------------------------------------------------
    def emit_extra_events(self, now: datetime) -> list[NormalisedEvent]:
        """Emit a command event whenever the commanded rate changes.

        Legitimate rate changes come from the clinical workstation inside the
        clinical VLAN during a nurse session. Attack-driven changes arrive
        from an off-segment source with no valid session, which is the
        signal the detector is expected to learn.
        """
        events: list[NormalisedEvent] = []
        previous = getattr(self, "_last_commanded", None)
        self._last_commanded = round(self.commanded_rate, 3)
        if previous is None or abs(previous - self.commanded_rate) < 0.05:
            return events

        self._command_seq += 1
        attacks = [
            a for a in self.active_attacks(now) if a.attack_type == AttackType.MALICIOUS_COMMAND
        ]
        malicious = bool(attacks)
        src_ip = attacks[0].source_ip if malicious else "10.0.10.20"
        events.append(
            NormalisedEvent(
                event_id=self.ids.event(),
                timestamp=now,
                kind=EventKind.DEVICE_COMMAND,
                device_id=self.profile.device_id,
                source_ip=src_ip,
                destination_ip=self.profile.ip_address,
                protocol="mqtt",
                destination_port=1883,
                measurements={
                    "requested_rate_ml_h": round(self.commanded_rate, 4),
                    "delta_rate_ml_h": round(self.commanded_rate - (previous or 0.0), 4),
                    "command_seq": float(self._command_seq),
                    "authenticated_session": 0.0 if malicious else 1.0,
                    "exceeds_safe_limit": float(self.commanded_rate > self.MAX_SAFE_RATE_ML_H),
                },
                attributes={
                    "command": "set_infusion_rate",
                    "operator_role": "unknown" if malicious else "nurse",
                    "session_id": "" if malicious else f"sess-{self.state.credentials_version}",
                    "source_segment": "unknown" if malicious else "vlan-clinical",
                },
            )
        )
        return events

    def on_control_applied(self, action) -> None:
        if action.name in {"rotate_credentials", "revoke_session"}:
            # Credential rotation invalidates the attacker's command channel.
            self.clear_attacks(AttackType.MALICIOUS_COMMAND)


__all__ = ["InfusionPump"]
