"""Non-clinical support assets.

The policy engine can only demonstrate *controlled autonomy* if there exist
genuinely low-criticality targets where autonomous action is defensible.
A clinical workstation and a network gateway provide that contrast class,
and they are also realistic initial footholds for an attacker.
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


class ClinicalWorkstation(SimulatedDevice):
    """Nurse-station workstation: non-clinical criticality, real foothold."""

    device_type = DeviceType.WORKSTATION

    def initialise(self) -> None:
        self.cpu_pct = 18.0
        self.disk_write_mb_s = 1.2
        self.process_count = 92.0
        self.failed_logins = 0.0
        self.encrypted_file_ops = 0.0
        self.state.delivering_therapy = False
        self.state.active_sessions = 1

    def advance_physiology(self, now: datetime) -> None:
        attacks = self.active_attacks(now)
        self.cpu_pct += (18.0 - self.cpu_pct) * 0.25 + self.jitter(1.6)
        self.disk_write_mb_s += (1.2 - self.disk_write_mb_s) * 0.3 + self.jitter(0.12)
        self.process_count += (92.0 - self.process_count) * 0.2 + self.jitter(1.0)
        self.failed_logins = max(0.0, self.failed_logins - 0.5)
        self.encrypted_file_ops = max(0.0, self.encrypted_file_ops - 2.0)

        for a in attacks:
            if a.attack_type == AttackType.CREDENTIAL_BRUTE_FORCE:
                self.failed_logins = min(240.0, self.failed_logins + 6.0 * a.intensity)
            elif a.attack_type == AttackType.RANSOMWARE_BEHAVIOUR:
                # Ransomware signature: CPU burn + sustained mass encrypted
                # writes. Counters are rates over the current window, so they
                # saturate rather than accumulate without bound.
                self.cpu_pct = min(100.0, self.cpu_pct + 42.0 * a.intensity)
                self.disk_write_mb_s = min(420.0, self.disk_write_mb_s + 55.0 * a.intensity)
                self.encrypted_file_ops = min(2500.0, self.encrypted_file_ops + 180.0 * a.intensity)
                self.process_count = min(400.0, self.process_count + 14.0)
            elif a.attack_type == AttackType.UNAUTHORIZED_ACCESS:
                self.state.active_sessions = 2

        self.cpu_pct = max(0.0, min(100.0, self.cpu_pct))
        self.state.alarm_active = self.encrypted_file_ops > 100.0 or self.failed_logins > 20.0
        self.state.alarm_reason = "suspicious_host_activity" if self.state.alarm_active else None
        if self.has_control("shutdown_device"):
            self.state.operational_state = DeviceOperationalState.OFFLINE

    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.TELEMETRY,
            device_id=self.profile.device_id,
            source_ip=self.profile.ip_address,
            source_mac=self.profile.mac_address,
            protocol="tcp",
            measurements={
                "cpu_pct": round(self.cpu_pct, 4),
                "disk_write_mb_s": round(self.disk_write_mb_s, 4),
                "process_count": round(self.process_count, 2),
                "failed_logins_window": round(self.failed_logins, 2),
                "encrypted_file_ops": round(self.encrypted_file_ops, 2),
                "active_sessions": float(self.state.active_sessions),
            },
            attributes={
                "device_type": self.device_type.value,
                "alarm": str(self.state.alarm_active).lower(),
                "alarm_reason": self.state.alarm_reason or "",
            },
        )

    def emit_extra_events(self, now: datetime) -> list[NormalisedEvent]:
        if self.failed_logins < 1.0:
            return []
        attacks = [
            a
            for a in self.active_attacks(now)
            if a.attack_type in {AttackType.CREDENTIAL_BRUTE_FORCE, AttackType.UNAUTHORIZED_ACCESS}
        ]
        src = attacks[0].source_ip if attacks else "10.0.10.44"
        return [
            NormalisedEvent(
                event_id=self.ids.event(),
                timestamp=now,
                kind=EventKind.AUTH,
                device_id=self.profile.device_id,
                source_ip=src,
                destination_ip=self.profile.ip_address,
                protocol="tcp",
                destination_port=3389,
                measurements={
                    "failed_attempts": round(self.failed_logins, 2),
                    "succeeded": float(bool(attacks) and self.failed_logins > 18.0),
                },
                attributes={
                    "auth_method": "password",
                    "username": "svc_backup" if attacks else "nurse01",
                    "result": "failure" if self.failed_logins > 1.0 else "success",
                },
            )
        ]


class NetworkGateway(SimulatedDevice):
    """Ward network gateway: aggregate flow statistics and ARP table state."""

    device_type = DeviceType.NETWORK_GATEWAY

    def initialise(self) -> None:
        self.pps = 820.0
        self.throughput_mbps = 44.0
        self.arp_table_changes = 0.0
        self.distinct_dst_ports = 6.0
        self.state.delivering_therapy = False

    def advance_physiology(self, now: datetime) -> None:
        attacks = self.active_attacks(now)
        self.pps += (820.0 - self.pps) * 0.3 + self.jitter(26.0)
        self.throughput_mbps += (44.0 - self.throughput_mbps) * 0.3 + self.jitter(1.8)
        self.arp_table_changes = max(0.0, self.arp_table_changes - 1.0)
        self.distinct_dst_ports += (6.0 - self.distinct_dst_ports) * 0.4 + self.jitter(0.4)

        for a in attacks:
            if a.attack_type == AttackType.DDOS:
                self.pps += 14000.0 * a.intensity
                self.throughput_mbps += 420.0 * a.intensity
            elif a.attack_type == AttackType.DOS:
                self.pps += 5200.0 * a.intensity
                self.throughput_mbps += 150.0 * a.intensity
            elif a.attack_type == AttackType.ARP_SPOOFING:
                self.arp_table_changes += 9.0 * a.intensity
            elif a.attack_type in {AttackType.PORT_SCAN, AttackType.RECONNAISSANCE}:
                self.distinct_dst_ports += 48.0 * a.intensity

        self.state.alarm_active = self.pps > 4000.0 or self.arp_table_changes > 6.0
        self.state.alarm_reason = "network_anomaly" if self.state.alarm_active else None

    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.TELEMETRY,
            device_id=self.profile.device_id,
            source_ip=self.profile.ip_address,
            protocol="snmp",
            measurements={
                "packets_per_second": round(self.pps, 2),
                "throughput_mbps": round(self.throughput_mbps, 3),
                "arp_table_changes": round(self.arp_table_changes, 2),
                "distinct_dst_ports": round(self.distinct_dst_ports, 2),
            },
            attributes={
                "device_type": self.device_type.value,
                "alarm": str(self.state.alarm_active).lower(),
                "alarm_reason": self.state.alarm_reason or "",
            },
        )


__all__ = ["ClinicalWorkstation", "NetworkGateway"]
