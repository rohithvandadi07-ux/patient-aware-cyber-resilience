"""Telemetry generation for simulated IoMT devices.

Architecture spec Section 9: "not random numbers, since detection-engine
evaluation is only meaningful against telemetry that looks like a real device."
Each generator produces a baseline value plus small, bounded, autocorrelated
noise (a slow random walk, not independent noise each tick) — which is closer to
how a real vital sign or mechanical reading actually drifts than i.i.d. noise
would be, and still cheap to compute.

Determinism: every generator takes a `random.Random` instance rather than using
the global `random` module. Callers (the simulator loop, tests, the
ScenarioRunner) own the seed, so "same seed → same sequence of readings" holds
without this module needing to know about seeding at all.
"""

import random
from datetime import datetime

from app.iomt_simulator.device import EcgMonitor, InfusionPump, SimulatedDevice, Ventilator
from app.schemas.telemetry import TelemetryReading


def _bounded_walk(rng: random.Random, current: float, step: float, low: float, high: float) -> float:
    """One step of a bounded random walk: nudges `current` by up to ±step, then
    clamps to [low, high]. This is the shared noise model behind every reading
    below — a real vital sign drifts smoothly rather than jumping independently
    each sample."""
    nudged = current + rng.uniform(-step, step)
    return max(low, min(high, nudged))


def generate_reading(device: SimulatedDevice, rng: random.Random, timestamp: datetime) -> TelemetryReading:
    """Produce one TelemetryReading for the given device, mutating the device's
    own baseline fields in place (so the next call continues the walk from here,
    not from the original default)."""

    if isinstance(device, InfusionPump):
        device.flow_rate_ml_per_hr = _bounded_walk(
            rng, device.flow_rate_ml_per_hr, step=1.5, low=0.0, high=500.0
        )
        readings = {"flow_rate_ml_per_hr": round(device.flow_rate_ml_per_hr, 2)}

    elif isinstance(device, Ventilator):
        device.respiratory_rate_bpm = _bounded_walk(
            rng, device.respiratory_rate_bpm, step=0.4, low=8.0, high=30.0
        )
        device.tidal_volume_ml = _bounded_walk(rng, device.tidal_volume_ml, step=5.0, low=200.0, high=800.0)
        readings = {
            "respiratory_rate_bpm": round(device.respiratory_rate_bpm, 1),
            "tidal_volume_ml": round(device.tidal_volume_ml, 1),
        }

    elif isinstance(device, EcgMonitor):
        device.heart_rate_bpm = _bounded_walk(rng, device.heart_rate_bpm, step=1.0, low=40.0, high=180.0)
        device.spo2_percent = _bounded_walk(rng, device.spo2_percent, step=0.3, low=85.0, high=100.0)
        readings = {
            "heart_rate_bpm": round(device.heart_rate_bpm, 1),
            "spo2_percent": round(device.spo2_percent, 1),
        }

    else:  # pragma: no cover - defensive; new device types must add a branch here
        raise TypeError(f"No telemetry generator registered for device type {type(device).__name__}")

    return TelemetryReading(device_id=device.device_id, timestamp=timestamp, readings=readings)
