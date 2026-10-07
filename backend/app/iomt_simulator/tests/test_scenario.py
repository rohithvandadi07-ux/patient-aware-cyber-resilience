"""Scenario-runner tests.

These are infrastructure tests for the simulator itself (does it tick
deterministically, does an injection fire where scripted) — not the architecture
spec's Section 17 Scenario A/B end-to-end tests, which require the detection
engine, risk engine, and policy engine to exist first (Phases 3, 5, 6) and belong
in the top-level `tests/` directory once those layers are built.
"""

from app.iomt_simulator.hospital import build_default_fleet
from app.iomt_simulator.scenario import AttackInjection, ScenarioRunner


def _run_scenario(seed: int = 42):
    registry = build_default_fleet()
    injection = AttackInjection(
        tick=6,
        device_id="ventilator-01",
        event_type="spoofed_command",
        payload={"command": "set_tidal_volume", "value": "50"},
        device_effect=lambda device: device.set_network_state("compromised"),
    )
    runner = ScenarioRunner(registry, seed=seed, injections=[injection])
    result = runner.run(num_ticks=10)
    return registry, result


def test_scenario_emits_telemetry_for_every_device_every_tick():
    _, result = _run_scenario()
    # 3 devices in the default fleet x 10 ticks
    assert len(result.telemetry) == 30


def test_attack_injection_fires_once_at_scripted_tick_for_target_device():
    _, result = _run_scenario()
    assert len(result.network_events) == 1
    event = result.network_events[0]
    assert event.device_id == "ventilator-01"
    assert event.event_type == "spoofed_command"
    assert event.is_attack_injection is True


def test_device_effect_mutates_target_device_state():
    registry, _ = _run_scenario()
    vent_state = registry.get_device_state("ventilator-01")
    assert vent_state.network_state == "compromised"


def test_other_devices_unaffected_by_injection_targeting_ventilator():
    registry, _ = _run_scenario()
    pump_state = registry.get_device_state("infusion-pump-01")
    assert pump_state.network_state == "connected"


def test_same_seed_is_fully_reproducible():
    _, result1 = _run_scenario(seed=42)
    _, result2 = _run_scenario(seed=42)

    telemetry1 = [t.model_dump() for t in result1.telemetry]
    telemetry2 = [t.model_dump() for t in result2.telemetry]
    assert telemetry1 == telemetry2

    events1 = [e.model_dump() for e in result1.network_events]
    events2 = [e.model_dump() for e in result2.network_events]
    assert events1 == events2


def test_different_seed_changes_telemetry_but_not_scripted_event_timing():
    _, result1 = _run_scenario(seed=42)
    _, result2 = _run_scenario(seed=99)

    telemetry1 = [t.model_dump() for t in result1.telemetry]
    telemetry2 = [t.model_dump() for t in result2.telemetry]
    assert telemetry1 != telemetry2  # noise differs

    # the injection is scripted by tick, not by RNG, so it still fires identically
    assert result1.network_events[0].model_dump() == result2.network_events[0].model_dump()
