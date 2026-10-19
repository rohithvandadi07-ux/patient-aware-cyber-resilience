"""Synthetic patient state: vitals and a NEWS2-style acuity score.

Synthetic data only -- never real patient data (brief Section 5). NEWS2 (Royal
College of Physicians, 2017) is used as a published, well-known early-warning
score. This is a simulation aid, not a clinical validation of the system.
"""

from enum import StrEnum

from pydantic import BaseModel, Field


class Consciousness(StrEnum):
    ALERT = "alert"
    CVPU = "cvpu"  # new confusion, or responds only to voice/pain, or unresponsive


class AcuityBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Vitals(BaseModel):
    respiration_rate: float = Field(description="breaths per minute")
    spo2: float = Field(description="oxygen saturation, % (NEWS2 scale 1)")
    on_supplemental_oxygen: bool
    systolic_bp: float = Field(description="mmHg")
    pulse: float = Field(description="beats per minute")
    consciousness: Consciousness
    temperature_c: float


class PatientState(BaseModel):
    patient_id: str
    device_ids: list[str] = Field(description="Devices this synthetic patient depends on.")
    profile: str = Field(description="Simulation profile that generates the vitals.")
    simulated_minute: int
    vitals: Vitals
    news2_score: int = Field(ge=0, le=20)
    score_breakdown: dict[str, int]
    single_parameter_red_flag: bool = Field(
        description="True if any single NEWS2 parameter scored 3."
    )
    acuity_band: AcuityBand