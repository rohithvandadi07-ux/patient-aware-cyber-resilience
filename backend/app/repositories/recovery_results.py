"""In-memory store for `RecoveryResult` records, queryable by incident_id.

Architecture spec Section 7, step 12: a failed recovery check "re-opens
[the incident] at step 4 with the new evidence appended." Section 11's
Recovery Verification Agent (`app/agents/recovery_verification.py`)
deliberately does not itself mutate incident status or persist its own
output -- that's L8 orchestration logic, explicitly deferred to Phase 7 in
that module's own docstring. For "the new evidence appended" to mean
something real rather than a phrase with nothing behind it, the actual
`RecoveryResult` has to be kept somewhere a later re-investigation (or a
human reviewing the incident) can read it back -- this store is that, in
the same in-memory-now pattern as `incidents.py`/`telemetry_events.py`,
until Phase 9 swaps it for a Postgres-backed repository with the same
query shape.
"""

from app.schemas.agents import RecoveryResult


class RecoveryResultRepository:
    def __init__(self) -> None:
        self._results: list[RecoveryResult] = []

    def record(self, result: RecoveryResult) -> None:
        self._results.append(result)

    def list_for_incident(self, incident_id: str) -> list[RecoveryResult]:
        """Every recovery check recorded for this incident, in the order
        recorded -- an incident can be checked more than once across a
        reopen loop, so this returns a list, not a single latest result."""
        return [r for r in self._results if r.incident_id == incident_id]

    def list_all(self) -> list[RecoveryResult]:
        """Every recovery check recorded across every incident, in the order
        recorded. Added in Phase 9 for the `/recovery` API router's
        unfiltered list endpoint -- the same kind of addition as
        `IncidentRepository.list_all`/`AgentTraceRecorder.all_traces`, not a
        change to this repository's existing query semantics."""
        return list(self._results)

    def clear(self) -> None:
        self._results.clear()
