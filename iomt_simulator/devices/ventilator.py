"""Simulated mechanical ventilator.

The ventilator is the platform's safety-critical anchor: it is the device
where the central thesis bites, because the maximally secure response
(isolate or shut down) can be the worst clinical response.

The model couples ventilator settings to a simple patient oxygenation
response, so that interrupting ventilation produces *observable clinical
deterioration* in telemetry. That coupling is what lets the evaluation
framework measure clinical harm caused by a response, rather than assuming
it.
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


class Ventilator(SimulatedDevice):
    """Pressure-controlled ventilator with coupled oxygenation model."""

    device_type = DeviceType.VENTILATOR

    SET_RR = 14.0  # breaths/min
    SET_TIDAL_ML = 450.0  # mL
    SET_PEEP = 5.0  # cmH2O
    SET_FIO2 = 0.40  # fraction
    SPO2_TARGET = 97.0
    SPO2_CRITICAL = 88.0

    def initialise(self) -> None:
        self.rr = self.SET_RR
        self.tidal_ml = self.SET_TIDAL_ML
        self.peep = self.SET_PEEP
        self.fio2 = self.SET_FIO2
        self.peak_pressure = 22.0
        self.minute_ventilation = self.rr * self.tidal_ml / 1000.0
        self.spo2 = self.SPO2_TARGET
        self.etco2 = 38.0
        self.ventilating = True
        self.state.delivering_therapy = True
        self.state.operational_state = DeviceOperationalState.ACTIVE
        self._apnea_seconds = 0.0
        self._settings_tampered = False

    # -- physiology --------------------------------------------------------
    def advance_physiology(self, now: datetime) -> None:
        attacks = self.active_attacks(now)
        self._settings_tampered = False

        for a in attacks:
            if a.attack_type == AttackType.MALICIOUS_COMMAND:
                # Attacker lowers respiratory support.
                self.rr = a.params.get("target_rr", 5.0)
                self.tidal_ml = a.params.get("target_tidal_ml", 180.0)
                self._settings_tampered = True
            elif a.attack_type == AttackType.SPOOFED_TELEMETRY:
                self._settings_tampered = True
            elif a.attack_type in {AttackType.DOS, AttackType.DDOS}:
                # Flooding degrades the control/monitoring channel. The
                # ventilator keeps ventilating (by safety design) but loses
                # remote observability, which itself is a clinical risk.
                self.state.fault_codes = sorted({*self.state.fault_codes, "COMMS_DEGRADED"})

        shut_down = self.has_control("shutdown_device") or (
            self.state.operational_state == DeviceOperationalState.OFFLINE
        )
        failed_over = self.has_control("failover_to_redundant_device")

        if shut_down or failed_over:
            self.ventilating = False
        elif not self._settings_tampered:
            self.ventilating = True
            self.rr += (self.SET_RR - self.rr) * 0.3
            self.tidal_ml += (self.SET_TIDAL_ML - self.tidal_ml) * 0.3

        if self.ventilating:
            self._apnea_seconds = 0.0
            self.minute_ventilation = self.rr * self.tidal_ml / 1000.0
            self.peak_pressure = 14.0 + 0.016 * self.tidal_ml + 0.9 * self.peep + self.jitter(0.4)
        else:
            self._apnea_seconds += self.tick_seconds
            self.minute_ventilation = 0.0
            self.peak_pressure = max(0.0, self.peak_pressure - 4.0)

        self.state.delivering_therapy = self.ventilating

        # Oxygenation response. Adequate minute ventilation holds SpO2 near
        # target; inadequate ventilation causes progressive desaturation.
        # A redundant ventilator taking over limits the deficit.
        adequate_mv = self.SET_RR * self.SET_TIDAL_ML / 1000.0
        if failed_over and self.profile.has_redundant_peer:
            effective_mv = adequate_mv * 0.9
        else:
            effective_mv = self.minute_ventilation

        ratio = effective_mv / adequate_mv if adequate_mv else 0.0
        if ratio >= 0.85:
            self.spo2 += (self.SPO2_TARGET - self.spo2) * 0.25 + self.jitter(0.12)
        else:
            # Desaturation rate scales with the ventilation deficit.
            # Desaturation rate scales with the ventilation deficit.
            # Calibrated so that total loss of ventilation reaches the
            # critical threshold (<88%) in roughly 60-90 s, consistent with
            # published apnoea desaturation times for a pre-oxygenated
            # adult patient. Asymptotes toward a survivable floor rather
            # than falling without bound.
            deficit = 1.0 - ratio
            floor = 62.0
            rate = (0.09 + 0.17 * deficit) * self.tick_seconds
            self.spo2 -= rate * max(0.15, (self.spo2 - floor) / 35.0)
            self.spo2 -= abs(self.jitter(0.015))
        self.spo2 = max(60.0, min(100.0, self.spo2))

        self.etco2 += ((38.0 if ratio >= 0.85 else 38.0 + 26.0 * (1.0 - ratio)) - self.etco2) * 0.2
        self.fio2 = max(0.21, min(1.0, self.fio2 + self.jitter(0.003)))

        desat = self.spo2 < 92.0
        critical_desat = self.spo2 < self.SPO2_CRITICAL
        apnea = self._apnea_seconds >= 20.0
        low_mv = self.ventilating and self.minute_ventilation < adequate_mv * 0.6

        self.state.alarm_active = bool(desat or apnea or low_mv)
        if critical_desat:
            self.state.alarm_reason = "critical_desaturation"
        elif apnea:
            self.state.alarm_reason = "apnea_no_ventilation"
        elif desat:
            self.state.alarm_reason = "desaturation"
        elif low_mv:
            self.state.alarm_reason = "low_minute_ventilation"
        else:
            self.state.alarm_reason = None

        if critical_desat or apnea:
            self.state.operational_state = DeviceOperationalState.FAULT
            self.state.fault_codes = sorted({*self.state.fault_codes, "PATIENT_AT_RISK"})
        elif self.state.alarm_active:
            if self.state.operational_state not in {
                DeviceOperationalState.OFFLINE,
                DeviceOperationalState.QUARANTINED,
                DeviceOperationalState.ISOLATED,
            }:
                self.state.operational_state = DeviceOperationalState.ALARM
        elif self.state.operational_state in {
            DeviceOperationalState.ALARM,
            DeviceOperationalState.FAULT,
        }:
            self.state.operational_state = DeviceOperationalState.ACTIVE
            self.state.fault_codes = [c for c in self.state.fault_codes if c != "PATIENT_AT_RISK"]

    # -- telemetry ---------------------------------------------------------
    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        attacks = self.active_attacks(now)
        spoofing = any(a.attack_type == AttackType.SPOOFED_TELEMETRY for a in attacks)

        # Under telemetry spoofing the *reported* values look healthy while
        # the true values deteriorate. Ground-truth values are kept in a
        # separate namespace so the evaluation framework can measure the
        # gap, but detection only ever sees the reported fields.
        reported_spo2 = self.SPO2_TARGET + self.jitter(0.3) if spoofing else self.spo2
        reported_rr = self.SET_RR + self.jitter(0.2) if spoofing else self.rr
        reported_tidal = self.SET_TIDAL_ML + self.jitter(4.0) if spoofing else self.tidal_ml

        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.TELEMETRY,
            device_id=self.profile.device_id,
            source_ip=self.profile.ip_address,
            source_mac=self.profile.mac_address,
            protocol="mqtt",
            measurements={
                "respiratory_rate": round(reported_rr, 4),
                "tidal_volume_ml": round(reported_tidal, 4),
                "minute_ventilation_l_min": round(reported_rr * reported_tidal / 1000.0, 4),
                "peep_cmh2o": round(self.peep, 4),
                "peak_pressure_cmh2o": round(self.peak_pressure, 4),
                "fio2_fraction": round(self.fio2, 4),
                "spo2_pct": round(reported_spo2, 4),
                "etco2_mmhg": round(self.etco2, 4),
                # Internal-truth channel, never used as a detection feature.
                "truth_spo2_pct": round(self.spo2, 4),
                "truth_minute_ventilation_l_min": round(self.minute_ventilation, 4),
            },
            attributes={
                "device_type": self.device_type.value,
                "ventilating": str(self.ventilating).lower(),
                "alarm": str(self.state.alarm_active).lower(),
                "alarm_reason": self.state.alarm_reason or "",
                "mode": "PCV",
            },
        )

    def emit_extra_events(self, now: datetime) -> list[NormalisedEvent]:
        events: list[NormalisedEvent] = []
        previous = getattr(self, "_last_settings", None)
        current = (round(self.rr, 2), round(self.tidal_ml, 1))
        self._last_settings = current
        if previous is None or previous == current:
            return events

        attacks = [
            a for a in self.active_attacks(now) if a.attack_type == AttackType.MALICIOUS_COMMAND
        ]
        malicious = bool(attacks)
        events.append(
            NormalisedEvent(
                event_id=self.ids.event(),
                timestamp=now,
                kind=EventKind.DEVICE_COMMAND,
                device_id=self.profile.device_id,
                source_ip=attacks[0].source_ip if malicious else "10.0.10.20",
                destination_ip=self.profile.ip_address,
                protocol="mqtt",
                destination_port=1883,
                measurements={
                    "requested_rr": round(self.rr, 4),
                    "requested_tidal_ml": round(self.tidal_ml, 4),
                    "authenticated_session": 0.0 if malicious else 1.0,
                    "reduces_support": float(
                        self.rr < self.SET_RR * 0.8 or self.tidal_ml < self.SET_TIDAL_ML * 0.8
                    ),
                },
                attributes={
                    "command": "set_ventilation_parameters",
                    "operator_role": "unknown" if malicious else "respiratory_therapist",
                    "source_segment": "unknown" if malicious else "vlan-clinical",
                },
            )
        )
        return events

    def on_control_applied(self, action) -> None:
        # Session-based attacks are cleared by the base class.
        if action.name == "restart_device_service":
            self.rr = self.SET_RR
            self.tidal_ml = self.SET_TIDAL_ML
            self.ventilating = True


__all__ = ["Ventilator"]
