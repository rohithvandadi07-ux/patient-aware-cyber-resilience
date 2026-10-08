"""Declarative scenario specification.

A scenario is pure data: fleet composition, synthetic patient dependency,
attack schedule and seed. Scenarios therefore serialise to YAML, which is
what lets an experiment be cited in a paper and re-run byte-identically.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from backend.app.domain.enums import (
    AcuityLevel,
    AttackType,
    CriticalityTier,
    DeviceType,
    PatientDependencyLevel,
)
from backend.app.domain.models import DeviceProfile, SyntheticPatientContext
from iomt_simulator.attacks.injector import AttackSchedule


class PatientSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patient_ref: str
    acuity: AcuityLevel = AcuityLevel.STABLE
    dependency: PatientDependencyLevel = PatientDependencyLevel.CONTINUOUS
    on_life_support: bool = False
    clinician_present: bool = True
    tolerable_interruption_minutes: float = 30.0

    def to_context(self) -> SyntheticPatientContext:
        return SyntheticPatientContext(**self.model_dump())


class DeviceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    device_type: DeviceType
    model_name: str = "simulated"
    ward: str = "ICU-1"
    criticality: CriticalityTier = CriticalityTier.CLINICALLY_SIGNIFICANT
    life_support_relevant: bool = False
    has_redundant_peer: bool = False
    redundant_peer_id: str | None = None
    supports_safe_failover: bool = False
    acceptable_interruption_seconds: float = 300.0
    network_segment: str = "vlan-clinical"
    ip_address: str = "10.0.0.1"
    mac_address: str = "00:00:00:00:00:00"
    firmware_version: str = "1.0.0"
    patient: PatientSpec | None = None

    def to_profile(self) -> DeviceProfile:
        data = self.model_dump(exclude={"patient"})
        return DeviceProfile(
            **data,
            patient=self.patient.to_context() if self.patient else None,
        )


class AttackSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_type: AttackType
    target_device_id: str
    start_tick: int
    duration_ticks: int | None = None
    intensity: float = Field(default=1.0, gt=0.0, le=5.0)
    source_ip: str = "10.66.6.66"
    source_mac: str = "de:ad:be:ef:00:01"
    params: dict[str, float] = Field(default_factory=dict)
    label: str = ""

    def to_schedule(self) -> AttackSchedule:
        return AttackSchedule(**self.model_dump())


class ScenarioSpec(BaseModel):
    """A complete, reproducible simulation scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    description: str = ""
    seed: int = 20260101
    tick_seconds: float = Field(default=1.0, gt=0.0)
    total_ticks: int = Field(default=300, gt=0)
    start_time: datetime | None = None
    devices: list[DeviceSpec] = Field(default_factory=list)
    attack_specs: list[AttackSpec] = Field(default_factory=list, alias="attacks")
    # Expected outcome, used by scenario tests to assert research behaviour
    # rather than to drive the simulation.
    expectations: dict[str, Any] = Field(default_factory=dict)

    @property
    def attacks(self) -> list[AttackSchedule]:
        return [a.to_schedule() for a in self.attack_specs]

    # -- (de)serialisation -------------------------------------------------
    @classmethod
    def from_yaml(cls, path: str | Path) -> ScenarioSpec:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(raw)

    def to_yaml(self, path: str | Path) -> None:
        data = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        Path(path).write_text(
            yaml.safe_dump(data, sort_keys=False, default_flow_style=False), encoding="utf-8"
        )


__all__ = ["AttackSpec", "DeviceSpec", "PatientSpec", "ScenarioSpec"]
