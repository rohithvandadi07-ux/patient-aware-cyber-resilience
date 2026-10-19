"""Synthetic patients with deterministic, time-evolving vitals and a NEWS2 score.

Vitals are a pure function of (profile, patient_id, simulated minute): a
baseline, a linear drift per hour, and small noise from a seeded RNG, so the
same minute always gives the same vitals and demos are reproducible.

Acuity bands (simplified from NEWS2 clinical response levels):
  HIGH   : aggregate score >= 7
  MEDIUM : aggregate score 5-6, or any single parameter scoring 3
  LOW    : otherwise
SpO2 scale 1 only (no hypercapnic respiratory failure scale).
"""

import random
from dataclasses import dataclass, field

from app.schemas.patient import AcuityBand, Consciousness, PatientState, Vitals

_RANGES = {
    "respiration_rate": (4.0, 40.0),
    "spo2": (70.0, 100.0),
    "systolic_bp": (60.0, 220.0),
    "pulse": (30.0, 180.0),
    "temperature_c": (34.0, 41.0),
}
_NOISE = {
    "respiration_rate": 0.8,
    "spo2": 0.6,
    "systolic_bp": 3.0,
    "pulse": 3.0,
    "temperature_c": 0.1,
}


class PatientNotFoundError(KeyError):
    pass


@dataclass(frozen=True)
class PatientProfile:
    name: str
    baseline: dict[str, float]
    oxygen: bool
    drift_per_hour: dict[str, float] = field(default_factory=dict)
    cvpu_after_minute: int | None = None


def _score_rr(value: float) -> int:
    r = round(value)
    if r <= 8:
        return 3
    if r <= 11:
        return 1
    if r <= 20:
        return 0
    if r <= 24:
        return 2
    return 3


def _score_spo2(value: float) -> int:
    s = round(value)
    if s <= 91:
        return 3
    if s <= 93:
        return 2
    if s <= 95:
        return 1
    return 0


def _score_sbp(value: float) -> int:
    b = round(value)
    if b <= 90:
        return 3
    if b <= 100:
        return 2
    if b <= 110:
        return 1
    if b <= 219:
        return 0
    return 3


def _score_pulse(value: float) -> int:
    p = round(value)
    if p <= 40:
        return 3
    if p <= 50:
        return 1
    if p <= 90:
        return 0
    if p <= 110:
        return 1
    if p <= 130:
        return 2
    return 3


def _score_temp(value: float) -> int:
    t = round(value, 1)
    if t <= 35.0:
        return 3
    if t <= 36.0:
        return 1
    if t <= 38.0:
        return 0
    if t <= 39.0:
        return 1
    return 2


def news2(vitals: Vitals) -> tuple[int, dict[str, int], bool, AcuityBand]:
    """Returns (aggregate score, per-parameter breakdown, single-parameter red
    flag, acuity band)."""
    breakdown = {
        "respiration_rate": _score_rr(vitals.respiration_rate),
        "spo2": _score_spo2(vitals.spo2),
        "supplemental_oxygen": 2 if vitals.on_supplemental_oxygen else 0,
        "systolic_bp": _score_sbp(vitals.systolic_bp),
        "pulse": _score_pulse(vitals.pulse),
        "consciousness": 3 if vitals.consciousness == Consciousness.CVPU else 0,
        "temperature": _score_temp(vitals.temperature_c),
    }
    total = sum(breakdown.values())
    red_flag = any(score == 3 for score in breakdown.values())
    if total >= 7:
        band = AcuityBand.HIGH
    elif total >= 5 or red_flag:
        band = AcuityBand.MEDIUM
    else:
        band = AcuityBand.LOW
    return total, breakdown, red_flag, band


def vitals_at(profile: PatientProfile, patient_id: str, minute: int) -> Vitals:
    rng = random.Random(f"{patient_id}:{minute}")
    hours = minute / 60.0
    values: dict[str, float] = {}
    for key, (low, high) in _RANGES.items():
        raw = (
            profile.baseline[key]
            + profile.drift_per_hour.get(key, 0.0) * hours
            + rng.uniform(-_NOISE[key], _NOISE[key])
        )
        values[key] = round(min(max(raw, low), high), 1)
    cvpu = profile.cvpu_after_minute is not None and minute >= profile.cvpu_after_minute
    return Vitals(
        **values,
        on_supplemental_oxygen=profile.oxygen,
        consciousness=Consciousness.CVPU if cvpu else Consciousness.ALERT,
    )


class PatientRegistry:
    """In-memory simulated patients plus one shared simulated clock (minutes)."""

    def __init__(self) -> None:
        self._patients: dict[str, tuple[PatientProfile, list[str]]] = {}
        self._minute = 0

    @property
    def simulated_minute(self) -> int:
        return self._minute

    def register(self, patient_id: str, profile: PatientProfile, device_ids: list[str]) -> None:
        self._patients[patient_id] = (profile, list(device_ids))

    def advance(self, minutes: int) -> int:
        if minutes <= 0:
            raise ValueError("minutes must be positive")
        self._minute += minutes
        return self._minute

    def get_patient_state(self, patient_id: str) -> PatientState:
        try:
            profile, device_ids = self._patients[patient_id]
        except KeyError as exc:
            raise PatientNotFoundError(patient_id) from exc
        vitals = vitals_at(profile, patient_id, self._minute)
        score, breakdown, red_flag, band = news2(vitals)
        return PatientState(
            patient_id=patient_id,
            device_ids=device_ids,
            profile=profile.name,
            simulated_minute=self._minute,
            vitals=vitals,
            news2_score=score,
            score_breakdown=breakdown,
            single_parameter_red_flag=red_flag,
            acuity_band=band,
        )

    def list_patients(self) -> list[PatientState]:
        return [self.get_patient_state(pid) for pid in self._patients]

    def for_device(self, device_id: str) -> PatientState | None:
        for pid, (_, device_ids) in self._patients.items():
            if device_id in device_ids:
                return self.get_patient_state(pid)
        return None


_VENTILATED = PatientProfile(
    name="ventilated_critical",
    baseline={
        "respiration_rate": 24.0,
        "spo2": 93.0,
        "systolic_bp": 105.0,
        "pulse": 112.0,
        "temperature_c": 37.8,
    },
    oxygen=True,
)

_DETERIORATING = PatientProfile(
    name="stable_then_deteriorating",
    baseline={
        "respiration_rate": 16.0,
        "spo2": 97.0,
        "systolic_bp": 124.0,
        "pulse": 78.0,
        "temperature_c": 36.8,
    },
    oxygen=False,
    drift_per_hour={
        "respiration_rate": 3.0,
        "spo2": -1.5,
        "systolic_bp": -6.0,
        "pulse": 8.0,
        "temperature_c": 0.4,
    },
)


def build_default_patients() -> PatientRegistry:
    """Two synthetic patients matching `build_default_fleet()`'s
    `synthetic_patient_id` values: a ventilated, high-acuity patient and an
    ECG-monitored patient who starts stable and deteriorates over a few hours."""
    registry = PatientRegistry()
    registry.register("synthetic-patient-001", _VENTILATED, ["ventilator-01"])
    registry.register("synthetic-patient-002", _DETERIORATING, ["ecg-monitor-01"])
    return registry