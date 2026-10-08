"""Simulated ECG / multiparameter patient monitor.

The monitor is a *reporting* device: it does not deliver therapy, so
disrupting it does not directly harm the patient — but it blinds clinicians,
which is a real and different kind of clinical risk. This asymmetry is
deliberately modelled, because it is what gives the clinical-risk term
something non-trivial to distinguish.
"""

from __future__ import annotations

import math
from datetime import datetime

from backend.app.domain.enums import (
    AttackType,
    DeviceOperationalState,
    DeviceType,
    EventKind,
)
from backend.app.domain.models import NormalisedEvent
from iomt_simulator.base import SimulatedDevice


class ECGMonitor(SimulatedDevice):
    """Multiparameter monitor: HR, BP, SpO2, respiration, arrhythmia flags."""

    device_type = DeviceType.ECG_MONITOR

    BASE_HR = 78.0
    BASE_SYS = 118.0
    BASE_DIA = 74.0
    BASE_RESP = 16.0
    BASE_SPO2 = 97.0
    BASE_TEMP = 36.8

    def initialise(self) -> None:
        self.hr = self.BASE_HR
        self.systolic = self.BASE_SYS
        self.diastolic = self.BASE_DIA
        self.resp = self.BASE_RESP
        self.spo2 = self.BASE_SPO2
        self.temp = self.BASE_TEMP
        self.st_deviation_mv = 0.02
        self.arrhythmia = "none"
        self.monitoring = True
        self.state.delivering_therapy = False
        self.state.operational_state = DeviceOperationalState.ACTIVE
        self._phase = 0.0
        self._missed_samples = 0

    def advance_physiology(self, now: datetime) -> None:
        attacks = self.active_attacks(now)
        spoofing = any(a.attack_type == AttackType.SPOOFED_TELEMETRY for a in attacks)
        flooding = any(a.attack_type in {AttackType.DOS, AttackType.DDOS} for a in attacks)

        # Slow circadian-ish oscillation keeps the baseline non-stationary,
        # so anomaly detectors cannot trivially win with a constant model.
        self._phase += self.tick_seconds / 240.0
        osc = math.sin(self._phase)

        self.hr += (self.BASE_HR + 4.0 * osc - self.hr) * 0.2 + self.jitter(0.7)
        self.systolic += (self.BASE_SYS + 5.0 * osc - self.systolic) * 0.2 + self.jitter(1.1)
        self.diastolic += (self.BASE_DIA + 3.0 * osc - self.diastolic) * 0.2 + self.jitter(0.8)
        self.resp += (self.BASE_RESP - self.resp) * 0.2 + self.jitter(0.35)
        self.spo2 += (self.BASE_SPO2 - self.spo2) * 0.25 + self.jitter(0.22)
        self.temp += (self.BASE_TEMP - self.temp) * 0.1 + self.jitter(0.03)
        self.st_deviation_mv += (0.02 - self.st_deviation_mv) * 0.2 + self.jitter(0.004)
        self.spo2 = max(80.0, min(100.0, self.spo2))

        offline = self.has_control("shutdown_device") or (
            self.state.operational_state == DeviceOperationalState.OFFLINE
        )
        unreachable = not self.network_reachable

        # Monitoring continues at the bedside even when the network link is
        # cut; what is lost is *central* visibility. Flooding causes gaps.
        if flooding:
            self._missed_samples += 1
        else:
            self._missed_samples = max(0, self._missed_samples - 1)

        self.monitoring = not offline
        self.state.service_available = not offline and not unreachable

        gaps = self._missed_samples >= 5
        tachy = self.hr > 120.0
        brady = self.hr < 48.0
        hypox = self.spo2 < 90.0
        ischaemia = self.st_deviation_mv > 0.18

        if tachy:
            self.arrhythmia = "tachycardia"
        elif brady:
            self.arrhythmia = "bradycardia"
        else:
            self.arrhythmia = "none"

        self.state.alarm_active = bool(tachy or brady or hypox or ischaemia or gaps)
        if gaps:
            self.state.alarm_reason = "telemetry_gap_monitoring_degraded"
        elif hypox:
            self.state.alarm_reason = "hypoxaemia"
        elif ischaemia:
            self.state.alarm_reason = "st_deviation"
        elif tachy or brady:
            self.state.alarm_reason = self.arrhythmia
        else:
            self.state.alarm_reason = None

        if gaps or unreachable:
            self.state.fault_codes = sorted({*self.state.fault_codes, "MONITORING_DEGRADED"})
        else:
            self.state.fault_codes = [
                c for c in self.state.fault_codes if c != "MONITORING_DEGRADED"
            ]

        if offline:
            self.state.operational_state = DeviceOperationalState.OFFLINE
        elif self.state.alarm_active and self.state.operational_state not in {
            DeviceOperationalState.QUARANTINED,
            DeviceOperationalState.ISOLATED,
        }:
            self.state.operational_state = DeviceOperationalState.ALARM
        elif self.state.operational_state == DeviceOperationalState.ALARM:
            self.state.operational_state = DeviceOperationalState.ACTIVE

        self._spoofing = spoofing

    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        spoofing = getattr(self, "_spoofing", False)
        reported_hr = self.BASE_HR + self.jitter(0.4) if spoofing else self.hr
        reported_spo2 = self.BASE_SPO2 + self.jitter(0.2) if spoofing else self.spo2

        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.TELEMETRY,
            device_id=self.profile.device_id,
            source_ip=self.profile.ip_address,
            source_mac=self.profile.mac_address,
            protocol="hl7-mllp",
            destination_port=2575,
            measurements={
                "heart_rate_bpm": round(reported_hr, 4),
                "systolic_mmhg": round(self.systolic, 4),
                "diastolic_mmhg": round(self.diastolic, 4),
                "map_mmhg": round((self.systolic + 2.0 * self.diastolic) / 3.0, 4),
                "respiration_rpm": round(self.resp, 4),
                "spo2_pct": round(reported_spo2, 4),
                "temperature_c": round(self.temp, 4),
                "st_deviation_mv": round(self.st_deviation_mv, 5),
                "missed_samples": float(self._missed_samples),
                "truth_heart_rate_bpm": round(self.hr, 4),
                "truth_spo2_pct": round(self.spo2, 4),
            },
            attributes={
                "device_type": self.device_type.value,
                "arrhythmia": self.arrhythmia,
                "alarm": str(self.state.alarm_active).lower(),
                "alarm_reason": self.state.alarm_reason or "",
                "monitoring": str(self.monitoring).lower(),
            },
        )

    def on_control_applied(self, action) -> None:
        if action.name in {"rotate_credentials", "revoke_session"}:
            self.clear_attacks(AttackType.SPOOFED_TELEMETRY)
        if action.name == "restart_device_service":
            self._missed_samples = 0


__all__ = ["ECGMonitor"]
