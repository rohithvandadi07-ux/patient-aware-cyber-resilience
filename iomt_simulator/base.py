"""Base abstractions for simulated IoMT devices.

Every device is a deterministic state machine driven by discrete ticks. On
each tick a device:

1. advances its internal physiological/operational model,
2. emits normalised telemetry, network, command, auth and state events,
3. applies any active attack effects,
4. applies any control actions imposed by the response orchestrator.

Determinism is a hard requirement: a given ``(seed, scenario)`` pair must
produce a byte-identical event stream, because the experimental framework
depends on it. Each device therefore owns a private ``random.Random``
derived from the scenario seed and its own device id, so adding a device
cannot perturb another device's stream.
"""

from __future__ import annotations

import hashlib
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from backend.app.domain.enums import (
    AttackType,
    DeviceOperationalState,
    DeviceType,
    EventKind,
    NetworkState,
)
from backend.app.domain.ids import IdFactory
from backend.app.domain.models import DeviceProfile, DeviceState, NormalisedEvent


def derive_seed(scenario_seed: int, device_id: str) -> int:
    """Derive a stable per-device seed from the scenario seed.

    Uses a hash rather than ``scenario_seed + index`` so that device streams
    are independent and reordering the device list cannot change any single
    device's output.
    """
    h = hashlib.sha256(f"{scenario_seed}:{device_id}".encode()).digest()
    return int.from_bytes(h[:8], "big")


@dataclass
class AttackEffect:
    """An active attack's effect on a device, installed by the injector.

    The simulator models attacks as *effects on observable signals*, which is
    what keeps detection honest: the detector sees only telemetry, flows,
    commands and auth events, never the attack label.
    """

    attack_type: AttackType
    started_at: datetime
    ends_at: datetime | None = None
    intensity: float = 1.0
    source_ip: str = "10.66.6.66"
    source_mac: str = "de:ad:be:ef:00:01"
    # Free-form knobs interpreted per device/attack.
    params: dict[str, float] = field(default_factory=dict)

    def active_at(self, t: datetime) -> bool:
        if t < self.started_at:
            return False
        return self.ends_at is None or t <= self.ends_at


@dataclass
class ControlAction:
    """A control imposed on the device by the response orchestrator.

    The simulator is the actuation target: this is how a response such as
    ``QUARANTINE_DEVICE`` becomes observable in subsequent telemetry, and
    how recovery verification can detect side effects.
    """

    name: str
    applied_at: datetime
    params: dict[str, float] = field(default_factory=dict)


class SimulatedDevice(ABC):
    """Abstract base for all simulated IoMT assets."""

    device_type: DeviceType

    def __init__(
        self,
        profile: DeviceProfile,
        scenario_seed: int,
        ids: IdFactory,
        tick_seconds: float = 1.0,
    ) -> None:
        self.profile = profile
        self.ids = ids
        self.tick_seconds = tick_seconds
        self.rng = random.Random(derive_seed(scenario_seed, profile.device_id))
        self.state = DeviceState(
            device_id=profile.device_id,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            operational_state=DeviceOperationalState.ACTIVE,
            network_state=NetworkState.NORMAL,
            service_available=True,
        )
        self.attacks: list[AttackEffect] = []
        self.controls: list[ControlAction] = []
        self._tick_index = 0
        self._baseline_established = False
        self.initialise()

    # -- lifecycle ---------------------------------------------------------
    @abstractmethod
    def initialise(self) -> None:
        """Set up device-specific physiological/operational baseline."""

    @abstractmethod
    def advance_physiology(self, now: datetime) -> None:
        """Advance the device's internal model by one tick."""

    @abstractmethod
    def emit_telemetry(self, now: datetime) -> NormalisedEvent:
        """Produce this tick's telemetry event."""

    def emit_extra_events(self, now: datetime) -> list[NormalisedEvent]:
        """Device-specific additional events (commands, alarms). Optional."""
        return []

    # -- attack / control plumbing ----------------------------------------
    def install_attack(self, effect: AttackEffect) -> None:
        self.attacks.append(effect)

    def clear_attacks(self, attack_type: AttackType | None = None) -> None:
        if attack_type is None:
            self.attacks.clear()
        else:
            self.attacks = [a for a in self.attacks if a.attack_type != attack_type]

    def active_attacks(self, now: datetime) -> list[AttackEffect]:
        return [a for a in self.attacks if a.active_at(now)]

    def apply_control(self, action: ControlAction) -> None:
        """Apply a response action to the simulated device."""
        self.controls.append(action)
        name = action.name
        if name == "quarantine_device":
            self.state.network_state = NetworkState.SEGMENTED
            self.state.operational_state = DeviceOperationalState.QUARANTINED
        elif name == "isolate_network_segment":
            self.state.network_state = NetworkState.ISOLATED
            self.state.operational_state = DeviceOperationalState.ISOLATED
        elif name == "restrict_communication":
            self.state.network_state = NetworkState.RESTRICTED
        elif name == "revoke_session":
            self.state.active_sessions = 0
            self._invalidate_sessions()
        elif name == "rotate_credentials":
            self.state.credentials_version += 1
            self.state.active_sessions = 0
            self._invalidate_sessions()
        elif name == "restart_device_service":
            self.state.service_available = True
            self.state.fault_codes = []
            self.state.uptime_seconds = 0.0
        elif name == "shutdown_device":
            self.state.operational_state = DeviceOperationalState.OFFLINE
            self.state.service_available = False
            self.state.delivering_therapy = False
        elif name == "failover_to_redundant_device":
            self.state.operational_state = DeviceOperationalState.STANDBY
            self.state.delivering_therapy = False
        self.on_control_applied(action)

    def _invalidate_sessions(self) -> None:
        """Clear every attack that depends on an authenticated session.

        Credential rotation and session revocation remove the attacker's
        *session*, so any attack carried over that session stops - not just
        the command channel it happened to be using. Modelled once here so
        all devices behave consistently: previously the infusion pump
        cleared MALICIOUS_COMMAND but left UNAUTHORIZED_ACCESS installed, so
        rotating credentials appeared to have no effect on the session
        itself and recovery verification correctly reported the attack as
        still active. That was a simulator gap, not a recovery-engine fault.

        Kept deliberately in step with
        ``recovery.engine.MECHANISM_SEVERED_BY``: if an action is listed
        there as severing an attack, the simulator must actually sever it,
        or the two layers disagree and the recovery metrics become
        meaningless.
        """
        session_based = {
            AttackType.UNAUTHORIZED_ACCESS,
            AttackType.MALICIOUS_COMMAND,
            AttackType.SPOOFED_TELEMETRY,
            AttackType.CREDENTIAL_BRUTE_FORCE,
        }
        self.attacks = [a for a in self.attacks if a.attack_type not in session_based]

    def on_control_applied(self, action: ControlAction) -> None:  # noqa: B027
        """Hook for device-specific reaction to a control action.

        Intentionally concrete and empty: most devices need no extra
        reaction, so this is an optional override, not an abstract method.
        """

    def release_control(self, name: str) -> None:
        """Reverse a reversible control (used by recovery/rollback)."""
        self.controls = [c for c in self.controls if c.name != name]
        if name in {"quarantine_device", "isolate_network_segment", "restrict_communication"}:
            self.state.network_state = NetworkState.NORMAL
            if self.state.operational_state in {
                DeviceOperationalState.QUARANTINED,
                DeviceOperationalState.ISOLATED,
            }:
                self.state.operational_state = DeviceOperationalState.ACTIVE

    def has_control(self, name: str) -> bool:
        return any(c.name == name for c in self.controls)

    @property
    def network_reachable(self) -> bool:
        return self.state.network_state not in {NetworkState.ISOLATED, NetworkState.UNREACHABLE}

    # -- tick --------------------------------------------------------------
    def tick(self, now: datetime) -> list[NormalisedEvent]:
        """Advance one tick and return all events emitted."""
        self._tick_index += 1
        self.state.timestamp = now
        if self.state.operational_state != DeviceOperationalState.OFFLINE:
            self.state.uptime_seconds += self.tick_seconds
        if (
            self.state.delivering_therapy is False
            and self.profile.patient is not None
            and self.profile.patient.dependency.value in {"continuous", "life_critical"}
        ):
            self.state.therapy_interrupted_seconds += self.tick_seconds

        self.advance_physiology(now)
        events: list[NormalisedEvent] = []
        if self.state.operational_state != DeviceOperationalState.OFFLINE:
            events.append(self.emit_telemetry(now))
            events.extend(self.emit_extra_events(now))
        events.extend(self.emit_state_event(now))
        return events

    def emit_state_event(self, now: datetime) -> list[NormalisedEvent]:
        """Emit a device-state event when state changed since last tick."""
        signature = (
            self.state.operational_state.value,
            self.state.network_state.value,
            self.state.alarm_active,
            self.state.service_available,
            tuple(self.state.fault_codes),
        )
        previous = getattr(self, "_last_state_signature", None)
        self._last_state_signature = signature
        if previous is None or previous == signature:
            return []
        return [
            NormalisedEvent(
                event_id=self.ids.event(),
                timestamp=now,
                kind=EventKind.DEVICE_STATE,
                device_id=self.profile.device_id,
                source_ip=self.profile.ip_address,
                measurements={
                    "alarm_active": float(self.state.alarm_active),
                    "service_available": float(self.state.service_available),
                    "active_sessions": float(self.state.active_sessions),
                },
                attributes={
                    "operational_state": self.state.operational_state.value,
                    "network_state": self.state.network_state.value,
                    "alarm_reason": self.state.alarm_reason or "",
                    "fault_codes": ",".join(self.state.fault_codes),
                },
            )
        ]

    # -- helpers -----------------------------------------------------------
    def jitter(self, scale: float) -> float:
        """Symmetric gaussian jitter, clamped, for realistic telemetry."""
        return max(-3.0 * scale, min(3.0 * scale, self.rng.gauss(0.0, scale)))

    def duration_since(self, effect: AttackEffect, now: datetime) -> float:
        return max(0.0, (now - effect.started_at).total_seconds())

    def _elapsed(self, seconds: float) -> timedelta:
        return timedelta(seconds=seconds)


__all__ = [
    "AttackEffect",
    "ControlAction",
    "SimulatedDevice",
    "derive_seed",
]
