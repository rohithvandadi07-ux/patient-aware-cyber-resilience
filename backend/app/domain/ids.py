"""Deterministic, human-readable identifier generation.

Identifiers are prefixed so that any ID appearing in a log line, a ledger
entry or the dashboard is immediately attributable to a subsystem. A
``Clock``/``IdFactory`` pair is injected rather than reading the wall clock
directly, so experiments and tests are byte-for-byte reproducible.
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime


class Clock:
    """Injectable time source."""

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass
class FixedClock(Clock):
    """Deterministic clock for tests and reproducible experiments."""

    start: datetime
    step_seconds: float = 1.0
    _ticks: Iterator[int] = field(default_factory=lambda: itertools.count(), repr=False)

    def now(self) -> datetime:
        from datetime import timedelta

        n = next(self._ticks)
        return self.start + timedelta(seconds=self.step_seconds * n)

    def peek(self) -> datetime:
        return self.start


@dataclass
class IdFactory:
    """Generates prefixed identifiers.

    With ``deterministic=True`` the factory emits a reproducible sequence
    (``INC-000001``), which is what experiment runs and scenario tests use.
    Otherwise a short uuid4 suffix is used.
    """

    deterministic: bool = False
    _counters: dict[str, itertools.count] = field(default_factory=dict, repr=False)

    def _next(self, prefix: str) -> str:
        if prefix not in self._counters:
            self._counters[prefix] = itertools.count(1)
        return f"{prefix}-{next(self._counters[prefix]):06d}"

    def new(self, prefix: str) -> str:
        if self.deterministic:
            return self._next(prefix)
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    # Convenience accessors -------------------------------------------------
    def incident(self) -> str:
        return self.new("INC")

    def event(self) -> str:
        return self.new("EVT")

    def evidence(self) -> str:
        return self.new("EVD")

    def agent_run(self) -> str:
        return self.new("AGR")

    def response(self) -> str:
        return self.new("RSP")

    def approval(self) -> str:
        return self.new("APR")

    def recovery(self) -> str:
        return self.new("RCV")

    def correlation(self) -> str:
        return self.new("COR")

    def provenance(self) -> str:
        return self.new("PRV")

    def tool_call(self) -> str:
        return self.new("TLC")


def canonical_hash(payload: object) -> str:
    """Stable SHA-256 of a JSON-serialisable payload.

    Used for evidence integrity: the hash goes on-chain, the payload stays
    off-chain. Keys are sorted and separators fixed so the digest is stable
    across processes and Python versions.
    """
    import json

    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = ["Clock", "FixedClock", "IdFactory", "canonical_hash"]
