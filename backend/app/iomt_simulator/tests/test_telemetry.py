import random
from datetime import UTC, datetime

import pytest

from app.iomt_simulator.device import EcgMonitor, InfusionPump, Ventilator
from app.iomt_simulator.telemetry import generate_reading


@pytest.mark.parametrize(
    ("device_factory", "expected_keys"),
    [
        (
            lambda: InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False),
            {"flow_rate_ml_per_hr"},
        ),
        (
            lambda: Ventilator(device_id="vent-01", criticality="high", patient_dependency=True),
            {"respiratory_rate_bpm", "tidal_volume_ml"},
        ),
        (
            lambda: EcgMonitor(device_id="ecg-01", criticality="medium", patient_dependency=False),
            {"heart_rate_bpm", "spo2_percent"},
        ),
    ],
)
def test_generate_reading_produces_expected_fields(device_factory, expected_keys):
    device = device_factory()
    rng = random.Random(1)
    reading = generate_reading(device, rng, datetime.now(UTC))
    assert set(reading.readings.keys()) == expected_keys
    assert reading.device_id == device.device_id


def test_same_seed_produces_identical_sequence():
    def run(seed: int) -> list[dict]:
        rng = random.Random(seed)
        device = Ventilator(device_id="vent-01", criticality="high", patient_dependency=True)
        ts = datetime.now(UTC)
        return [generate_reading(device, rng, ts).readings for _ in range(10)]

    assert run(42) == run(42)


def test_different_seeds_diverge():
    def run(seed: int) -> list[dict]:
        rng = random.Random(seed)
        device = Ventilator(device_id="vent-01", criticality="high", patient_dependency=True)
        ts = datetime.now(UTC)
        return [generate_reading(device, rng, ts).readings for _ in range(10)]

    assert run(1) != run(2)


def test_readings_stay_within_clinically_plausible_bounds():
    rng = random.Random(7)
    device = EcgMonitor(device_id="ecg-01", criticality="medium", patient_dependency=False)
    ts = datetime.now(UTC)

    for _ in range(200):
        reading = generate_reading(device, rng, ts)
        assert 40.0 <= reading.readings["heart_rate_bpm"] <= 180.0
        assert 85.0 <= reading.readings["spo2_percent"] <= 100.0
