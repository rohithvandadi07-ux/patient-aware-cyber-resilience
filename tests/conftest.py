"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.domain.ids import FixedClock, IdFactory  # noqa: E402
from iomt_simulator.hospital import SmartHospital  # noqa: E402
from iomt_simulator.scenarios.library import get_scenario  # noqa: E402


@pytest.fixture
def ids() -> IdFactory:
    return IdFactory(deterministic=True)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(start=datetime(2026, 1, 1, 8, 0, tzinfo=UTC))


@pytest.fixture
def make_hospital(ids: IdFactory):
    def _make(scenario_name: str, ticks: int = 0) -> SmartHospital:
        h = SmartHospital(scenario=get_scenario(scenario_name), ids=IdFactory(deterministic=True))
        if ticks:
            h.run(ticks)
        return h

    return _make
