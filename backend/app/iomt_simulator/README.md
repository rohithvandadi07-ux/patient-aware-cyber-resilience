# iomt_simulator

L1 of the architecture. Simulated smart-hospital IoMT devices (infusion pump,
ventilator, ECG/patient monitor) as state machines with clinical attributes
(criticality, patient dependency, synthetic patient ID) and a telemetry generator
that produces plausible, bounded-noise readings — a slow random walk per field,
not independent random numbers each tick.

A separate `ScenarioRunner` injects controlled attack scenarios by mutating a
device's network-event stream in a scripted, reproducible way: same seed, same
injections, identical output every run.

Modules:
- `device.py` — `SimulatedDevice` state machine + `InfusionPump`/`Ventilator`/`EcgMonitor`
- `telemetry.py` — per-device-type reading generation (seeded, deterministic)
- `registry.py` — `DeviceRegistry`, the single source of truth for device state;
  `get_device_state` here is the function the Healthcare Context Agent will call
  as a tool once Phase 4 exists
- `hospital.py` — `build_default_fleet()`, the standard three-device fleet used by
  tests and the API
- `scenario.py` — `ScenarioRunner` + `AttackInjection` for deterministic,
  reproducible attack scenario injection
- `tests/` — unit tests for all of the above

Status: implemented (Phase 2). Wearable sensors remain out of scope per the brief
(marked optional); no real hardware/protocol integration.
