"""The simulated smart hospital.

Owns the device fleet, the network fabric and the attack injector, and
advances them in lockstep. This is the single actuation target for the
response orchestrator and the single event source for detection, which is
what makes the closed loop genuinely closed: a response changes device and
network state, and the *next* tick's telemetry reflects it.

Determinism contract
--------------------
``SmartHospital(scenario).run(n)`` produces an identical event stream for a
given scenario (including its seed) on any machine and Python 3.11+. The
test suite asserts this.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.domain.enums import (
    AttackType,
    EventKind,
)
from backend.app.domain.ids import IdFactory
from backend.app.domain.models import (
    DeviceProfile,
    DeviceState,
    NormalisedEvent,
)
from iomt_simulator.attacks.injector import HOST_ATTACKS, AttackInjector
from iomt_simulator.base import ControlAction, SimulatedDevice
from iomt_simulator.devices import DEVICE_CLASSES
from iomt_simulator.network.fabric import NetworkFabric
from iomt_simulator.scenarios.spec import ScenarioSpec


@dataclass
class SmartHospital:
    """Deterministic smart-hospital simulation."""

    scenario: ScenarioSpec
    ids: IdFactory = field(default_factory=lambda: IdFactory(deterministic=True))

    devices: dict[str, SimulatedDevice] = field(default_factory=dict, init=False)
    fabric: NetworkFabric = field(init=False)
    injector: AttackInjector = field(init=False)
    tick_index: int = field(default=0, init=False)
    started_at: datetime = field(init=False)
    event_log: list[NormalisedEvent] = field(default_factory=list, init=False)
    attack_start_times: dict[tuple[str, AttackType], datetime] = field(
        default_factory=dict, init=False
    )

    def __post_init__(self) -> None:
        self.started_at = self.scenario.start_time or datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
        self.fabric = NetworkFabric(
            scenario_seed=self.scenario.seed,
            ids=self.ids,
            tick_seconds=self.scenario.tick_seconds,
        )
        self.injector = AttackInjector(schedules=list(self.scenario.attacks))
        for spec in self.scenario.devices:
            profile = spec.to_profile()
            cls = DEVICE_CLASSES[profile.device_type.value]
            self.devices[profile.device_id] = cls(
                profile=profile,
                scenario_seed=self.scenario.seed,
                ids=self.ids,
                tick_seconds=self.scenario.tick_seconds,
            )

    # -- time --------------------------------------------------------------
    def time_at(self, tick: int) -> datetime:
        return self.started_at + timedelta(seconds=tick * self.scenario.tick_seconds)

    @property
    def now(self) -> datetime:
        return self.time_at(self.tick_index)

    # -- accessors ---------------------------------------------------------
    def profile(self, device_id: str) -> DeviceProfile | None:
        d = self.devices.get(device_id)
        return d.profile if d else None

    def state(self, device_id: str) -> DeviceState | None:
        d = self.devices.get(device_id)
        return d.state if d else None

    def all_profiles(self) -> list[DeviceProfile]:
        return [d.profile for d in self.devices.values()]

    def all_states(self) -> list[DeviceState]:
        return [d.state for d in self.devices.values()]

    # -- actuation ---------------------------------------------------------
    def apply_response(
        self, action_name: str, device_id: str | None = None, segment: str | None = None
    ) -> dict[str, Any]:
        """Actuate a response action against the simulation.

        Returns a structured result the response orchestrator records. This
        is the ONLY mutation path the orchestrator has into the simulator.
        """
        now = self.now
        affected: list[str] = []
        action = ControlAction(name=action_name, applied_at=now)

        if action_name == "isolate_network_segment" and segment:
            for d in self.devices.values():
                if d.profile.network_segment == segment:
                    d.apply_control(action)
                    affected.append(d.profile.device_id)
        elif action_name in {"block_source_traffic", "rate_limit_traffic"}:
            # Blocking the attacker's source stops network-borne attacks
            # against the target without touching the device itself.
            target = self.devices.get(device_id) if device_id else None
            if target:
                for t in (
                    AttackType.DOS,
                    AttackType.DDOS,
                    AttackType.PORT_SCAN,
                    AttackType.RECONNAISSANCE,
                    AttackType.ARP_SPOOFING,
                    AttackType.MITM,
                ):
                    target.clear_attacks(t)
                affected.append(target.profile.device_id)
        elif action_name == "monitor_only" or action_name == "escalate_to_clinical_staff":
            affected = [device_id] if device_id else []
        elif device_id and device_id in self.devices:
            self.devices[device_id].apply_control(action)
            affected.append(device_id)
            if action_name == "failover_to_redundant_device":
                peer_id = self.devices[device_id].profile.redundant_peer_id
                if peer_id and peer_id in self.devices:
                    self.devices[peer_id].state.operational_state = self.devices[
                        peer_id
                    ].state.operational_state
                    affected.append(peer_id)

        return {
            "action": action_name,
            "applied_at": now.isoformat(),
            "affected_devices": affected,
            "succeeded": bool(affected) or action_name in {"monitor_only"},
        }

    def release_response(self, action_name: str, device_id: str) -> bool:
        d = self.devices.get(device_id)
        if not d:
            return False
        d.release_control(action_name)
        return True

    # -- ticking -----------------------------------------------------------
    def tick(self) -> list[NormalisedEvent]:
        """Advance the simulation by exactly one tick."""
        now = self.time_at(self.tick_index)

        # 1. install scheduled attacks due at this tick
        for sched in self.injector.pending_at(self.tick_index):
            device = self.devices.get(sched.target_device_id)
            if device is None:
                continue
            device.install_attack(sched.to_effect(now, self.scenario.tick_seconds))
            self.attack_start_times.setdefault((sched.target_device_id, sched.attack_type), now)

        events: list[NormalisedEvent] = []

        # 2. advance each device (sorted for determinism)
        for device_id in sorted(self.devices):
            device = self.devices[device_id]
            device_events = device.tick(now)

            # Attach ground truth for supervised training/evaluation ONLY.
            #
            # Labelling discipline: an event is labelled with an attack only
            # if THAT event is a manifestation of the attack. A host-visible
            # attack (malicious command, telemetry spoofing, ransomware)
            # manifests in device telemetry/commands/auth; a network-borne
            # attack (DoS, scanning, ARP spoofing, MITM) manifests in flow
            # records, which the fabric labels itself. Blanket-labelling every
            # event from an attacked device would leak the label into
            # channels that carry no attack signal and silently inflate every
            # detection metric in the evaluation framework.
            host_truth = self.injector.ground_truth_at(self.tick_index, device_id)
            if host_truth is not None and host_truth not in HOST_ATTACKS:
                host_truth = None

            for ev in device_events:
                update: dict[str, Any] = {"scenario_id": self.scenario.scenario_id}
                if ev.ground_truth_attack is None and host_truth is not None:
                    update["ground_truth_attack"] = host_truth
                    update["ground_truth_is_attack"] = True
                elif ev.ground_truth_attack is None:
                    update["ground_truth_is_attack"] = False
                events.append(ev.model_copy(update=update))

            # 3. network flows for this device. The fabric labels each flow
            #    it generates; benign flows observed during an attack window
            #    remain benign-labelled.
            flows = self.fabric.flows_for_device(
                now=now,
                device_id=device_id,
                device_type=device.profile.device_type.value,
                ip=device.profile.ip_address,
                mac=device.profile.mac_address,
                network_state=device.state.network_state,
                attacks=device.active_attacks(now),
            )
            for fl in flows:
                events.append(fl.model_copy(update={"scenario_id": self.scenario.scenario_id}))

        self.tick_index += 1
        self.event_log.extend(events)
        return events

    def run(self, ticks: int) -> list[NormalisedEvent]:
        """Run ``ticks`` ticks and return all events produced."""
        produced: list[NormalisedEvent] = []
        for _ in range(ticks):
            produced.extend(self.tick())
        return produced

    def run_until(self, tick: int) -> list[NormalisedEvent]:
        if tick <= self.tick_index:
            return []
        return self.run(tick - self.tick_index)

    # -- introspection -----------------------------------------------------
    def recent_events(
        self,
        limit: int = 200,
        device_id: str | None = None,
        kinds: set[EventKind] | None = None,
    ) -> list[NormalisedEvent]:
        out = []
        for ev in reversed(self.event_log):
            if device_id and ev.device_id != device_id:
                continue
            if kinds and ev.kind not in kinds:
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return list(reversed(out))

    def attack_started_at(self, device_id: str, attack_type: AttackType) -> datetime | None:
        return self.attack_start_times.get((device_id, attack_type))

    def summary(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario.scenario_id,
            "seed": self.scenario.seed,
            "tick_index": self.tick_index,
            "simulated_time": self.now.isoformat(),
            "device_count": len(self.devices),
            "event_count": len(self.event_log),
            "attacks_scheduled": len(self.scenario.attacks),
            "attacks_installed": len(self.attack_start_times),
        }


__all__ = ["SmartHospital"]
