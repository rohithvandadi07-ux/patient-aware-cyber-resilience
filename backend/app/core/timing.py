"""Wall-clock stage timing for the detection-to-response path.

A tiny, dependency-free recorder: `with timings.stage("policy_engine"): ...`
accumulates the elapsed time under a name (summed if a stage runs more than
once, e.g. across a re-investigation). It measures this process's wall clock
only -- queueing, network and human time are not in it.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager


class StageTimings:
    def __init__(self) -> None:
        self._ms: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self._ms[name] = self._ms.get(name, 0.0) + (time.perf_counter() - start) * 1000.0

    def as_dict(self) -> dict[str, float]:
        return dict(self._ms)

    def total_ms(self) -> float:
        return sum(self._ms.values())
