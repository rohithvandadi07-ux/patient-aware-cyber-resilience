"""Deterministic attack-scenario injection.

Architecture spec Section 9: "A separate `ScenarioRunner` injects controlled
attack scenarios [...] by mutating a device's network-event stream in a
scripted, reproducible way — same scenario, same seed, same sequence of events
every run," which Section 17's two deterministic test scenarios and Section 18's
experiments both depend on.

Design: a `ScenarioRunner` ticks a device registry forward a fixed number of
steps, emitting one `TelemetryReading` per device per tick, drawn from a single
seeded `random.Random` shared across every device so the whole run's output is
reproducible from one seed. At a scripted tick, an `AttackInjection` fires: it
emits one or more `NetworkEvent`s tagged `is_attack_injection=True` and may also
mutate the target device's operational/network state to reflect the attack's
simulated effect (e.g. a spoofed command actually changing a reading, or a DoS
scenario degrading network_state).

This module does not call the detection engine, the agents, or the policy
engine — those don't exist yet (Phases 3-6). It only produces the event stream
those layers will later consume. Keeping it decoupled is what Section 17's tests
depend on: a scenario run must be assertable on its own (did the right events
fire, at the right tick, for the right device) before anything downstream exists
to react to it.
"""

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.iomt_simulator.device import SimulatedDevice
from app.iomt_simulator.registry import DeviceRegistry
from app.iomt_simulator.telemetry import generate_reading
from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading


@dataclass
class AttackInjection:
    """A single scripted attack event, fired at a specific tick against a
    specific device."""

    tick: int
    device_id: str
    event_type: str
    source: str = "scenario_runner"
    payload: dict[str, str] = field(default_factory=dict)
    # Optional side effect applied to the target device when this injection
    # fires, e.g. `lambda device: device.set_network_state("degraded")` for a
    # DoS scenario. Kept optional because not every attack has a direct,
    # simple device-state mutation (e.g. pure reconnaissance does not).
    device_effect: Callable[[SimulatedDevice], None] | None = None


@dataclass
class ScenarioResult:
    """Everything a test or an experiment needs to assert on, without having to
    re-derive it from side effects on the registry."""

    telemetry: list[TelemetryReading]
    network_events: list[NetworkEvent]


class ScenarioRunner:
    """Ticks a device registry forward, emitting telemetry and firing any
    scripted attack injections at their designated tick.

    Reproducibility: pass the same `seed` and the same `injections` and the
    `telemetry` and `network_events` lists in the returned `ScenarioResult` will
    be identical, call for call, run for run.
    """

    def __init__(
        self,
        registry: DeviceRegistry,
        seed: int,
        injections: list[AttackInjection] | None = None,
        tick_duration_seconds: int = 5,
        start_time: datetime | None = None,
    ) -> None:
        self.registry = registry
        self.rng = random.Random(seed)
        self.injections = injections or []
        self.tick_duration = timedelta(seconds=tick_duration_seconds)
        self.start_time = start_time or datetime(2026, 1, 1, tzinfo=UTC)

    def run(self, num_ticks: int) -> ScenarioResult:
        telemetry: list[TelemetryReading] = []
        network_events: list[NetworkEvent] = []

        injections_by_tick: dict[int, list[AttackInjection]] = {}
        for injection in self.injections:
            injections_by_tick.setdefault(injection.tick, []).append(injection)

        for tick in range(num_ticks):
            timestamp = self.start_time + tick * self.tick_duration

            for device in self.registry.all_devices():
                reading = generate_reading(device, self.rng, timestamp)
                telemetry.append(reading)

            for injection in injections_by_tick.get(tick, []):
                device = self.registry.get(injection.device_id)
                if injection.device_effect is not None:
                    injection.device_effect(device)

                network_events.append(
                    NetworkEvent(
                        device_id=injection.device_id,
                        timestamp=timestamp,
                        event_type=injection.event_type,
                        source=injection.source,
                        payload=injection.payload,
                        is_attack_injection=True,
                    )
                )

        return ScenarioResult(telemetry=telemetry, network_events=network_events)
