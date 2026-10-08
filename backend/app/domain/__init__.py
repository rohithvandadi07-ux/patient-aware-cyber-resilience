"""Shared domain layer: enums, identifiers and value objects.

Nothing in this package may import from ``backend.app.api``,
``backend.app.db`` or any engine package. The dependency arrow points
inward: engines depend on the domain, never the reverse.
"""

from backend.app.domain.enums import *  # noqa: F403
from backend.app.domain.ids import Clock, FixedClock, IdFactory, canonical_hash

__all__ = ["Clock", "FixedClock", "IdFactory", "canonical_hash"]
