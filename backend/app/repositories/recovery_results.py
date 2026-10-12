"""Recovery-result store -- in-memory by default, a real Postgres-backed
implementation available via `Settings.repository_backend = "postgres"`.

Architecture spec Section 7, step 12: a failed recovery check "re-opens
[the incident] at step 4 with the new evidence appended." Section 11's
Recovery Verification Agent (`app/agents/recovery_verification.py`)
deliberately does not itself mutate incident status or persist its own
output -- that's L8 orchestration logic, explicitly deferred to Phase 7 in
that module's own docstring. For "the new evidence appended" to mean
something real rather than a phrase with nothing behind it, the actual
`RecoveryResult` has to be kept somewhere a later re-investigation (or a
human reviewing the incident) can read it back -- this store is that.
`RecoveryResultRepository` (below) was Phase 7's in-memory stand-in;
`PostgresRecoveryResultRepository`, added later, is the real Postgres-backed
one -- same public methods, backed by the `recovery_results` table
(`app/models/orm.py`) instead of a list.
"""

from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import RecoveryResultORM
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


def _result_from_row(row: RecoveryResultORM) -> RecoveryResult:
    return RecoveryResult(
        incident_id=row.incident_id,
        response_id=row.response_id,
        containment_verified=row.containment_verified,
        residual_threats=list(row.residual_threats),
        recovery_succeeded=row.recovery_succeeded,
        reinvestigation_required=row.reinvestigation_required,
    )


class PostgresRecoveryResultRepository:
    """Real, Postgres-backed `RecoveryResultRepository` -- same public
    interface, backed by the `recovery_results` table (`app/models/orm.py`)
    instead of a list. One short-lived session per call (`session_scope`),
    matching `PostgresIncidentRepository`'s pattern.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(self, result: RecoveryResult) -> None:
        with session_scope(self._session_factory) as session:
            row = RecoveryResultORM(
                incident_id=result.incident_id,
                response_id=result.response_id,
                containment_verified=result.containment_verified,
                residual_threats=list(result.residual_threats),
                recovery_succeeded=result.recovery_succeeded,
                reinvestigation_required=result.reinvestigation_required,
            )
            session.add(row)
            session.flush()

    def list_for_incident(self, incident_id: str) -> list[RecoveryResult]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(RecoveryResultORM)
                .filter(RecoveryResultORM.incident_id == incident_id)
                .all()
            )
            return [_result_from_row(row) for row in rows]

    def list_all(self) -> list[RecoveryResult]:
        with session_scope(self._session_factory) as session:
            rows = session.query(RecoveryResultORM).all()
            return [_result_from_row(row) for row in rows]

    def clear(self) -> None:
        """Test-only convenience, mirroring the in-memory repository's
        `clear()` -- deletes every row in `recovery_results` rather than
        dropping/recreating the table."""
        with session_scope(self._session_factory) as session:
            session.query(RecoveryResultORM).delete()
