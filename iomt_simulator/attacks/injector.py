"""Controlled attack injection.

SAFETY BOUNDARY
---------------
This module injects *effects on simulated observable signals*. It contains
no exploit code, no payloads, no network transmission and no capability
that could affect a real device. It cannot act outside the in-process
simulator. See docs/limitations.md.

Each attack is declared as a scheduled window with an intensity profile, so
scenarios are fully specified data rather than imperative code — which is
what makes experiments reproducible and comparable across runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from backend.app.domain.enums import AttackType
from iomt_simulator.base import AttackEffect

# Attacks that primarily manifest in the network fabric rather than on the
# device's own telemetry.
NETWORK_ATTACKS = {
    AttackType.DOS,
    AttackType.DDOS,
    AttackType.PORT_SCAN,
    AttackType.RECONNAISSANCE,
    AttackType.ARP_SPOOFING,
    AttackType.MITM,
}

# Attacks that manifest on the device/host itself.
HOST_ATTACKS = {
    AttackType.MALICIOUS_COMMAND,
    AttackType.SPOOFED_TELEMETRY,
    AttackType.UNAUTHORIZED_ACCESS,
    AttackType.CREDENTIAL_BRUTE_FORCE,
    AttackType.FIRMWARE_TAMPER,
    AttackType.RANSOMWARE_BEHAVIOUR,
}


@dataclass
class AttackSchedule:
    """Declarative specification of one attack in a scenario."""

    attack_type: AttackType
    target_device_id: str
    start_tick: int
    duration_ticks: int | None = None
    intensity: float = 1.0
    source_ip: str = "10.66.6.66"
    source_mac: str = "de:ad:be:ef:00:01"
    params: dict[str, float] = field(default_factory=dict)
    # If set, the attack stops when this response action is executed.
    stopped_by_actions: list[str] = field(default_factory=list)
    label: str = ""

    def to_effect(self, start_time: datetime, tick_seconds: float) -> AttackEffect:
        ends_at = (
            start_time + timedelta(seconds=self.duration_ticks * tick_seconds)
            if self.duration_ticks is not None
            else None
        )
        return AttackEffect(
            attack_type=self.attack_type,
            started_at=start_time,
            ends_at=ends_at,
            intensity=self.intensity,
            source_ip=self.source_ip,
            source_mac=self.source_mac,
            params=dict(self.params),
        )


@dataclass
class AttackInjector:
    """Applies scheduled attacks to devices at the correct ticks."""

    schedules: list[AttackSchedule] = field(default_factory=list)
    _installed: set[int] = field(default_factory=set, repr=False)

    def pending_at(self, tick: int) -> list[AttackSchedule]:
        out = []
        for i, s in enumerate(self.schedules):
            if s.start_tick == tick and i not in self._installed:
                self._installed.add(i)
                out.append(s)
        return out

    def ground_truth_at(self, tick: int, device_id: str) -> AttackType | None:
        """Ground-truth label for (tick, device), used only for evaluation."""
        for s in self.schedules:
            if s.target_device_id != device_id:
                continue
            end = s.start_tick + s.duration_ticks if s.duration_ticks is not None else float("inf")
            if s.start_tick <= tick < end:
                return s.attack_type
        return None

    def reset(self) -> None:
        self._installed.clear()


__all__ = ["HOST_ATTACKS", "NETWORK_ATTACKS", "AttackInjector", "AttackSchedule"]
