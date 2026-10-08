"""Shared pytest fixtures and process-wide resource limits."""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Resource limits - MUST run before numpy/sklearn are imported
# ---------------------------------------------------------------------------
# The suite fits many models in one process. Unbounded BLAS and joblib thread
# pools oversubscribe a small CI container and the run is OOM-killed
# (observed: exit 137 on a 2-core / 8 GB sandbox). These variables are read
# at numeric-library import time, so they are set at the very top of
# conftest, before any other import below.
for _var in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ.setdefault(_var, "1")
# Note: JOBLIB_START_METHOD is NOT set here - it expects a multiprocessing
# context name ("fork"/"spawn"), and "threading" raises at joblib import.
# Capping the thread counts above is what prevents the oversubscription.

import sys  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

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
