"""Incident repository -- in-memory by default, a real Postgres-backed
implementation available via `Settings.repository_backend = "postgres"`.

Architecture spec Section 8: incidents eventually live in PostgreSQL, with
foreign keys enforcing that an incident always references a real device.
`IncidentRepository` (below) was Phase 4's in-memory stand-in, built so that
swapping it for a real Postgres-backed implementation would be "a
constructor change for callers, not an API rewrite" -- which is exactly
what `PostgresIncidentRepository`, added later (see its own docstring for
scope and the sync-driver tradeoff), actually is: the same public methods,
same signatures, same return types, backed by a real `incidents` table
instead of a dict. `app/core/app_factory.py` picks which one to construct.
"""

from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import IncidentORM
from app.schemas.enums import IncidentStatus
from app.schemas.incident import Incident


class IncidentNotFoundError(KeyError):
    """Raised when an incident_id has no corresponding record."""


class IncidentRepository:
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}

    def create(self, incident_id: str, device_id: str) -> Incident:
        if incident_id in self._incidents:
            raise ValueError(f"Incident '{incident_id}' already exists")
        now = datetime.now(UTC)
        incident = Incident(
            incident_id=incident_id,
            device_id=device_id,
            status=IncidentStatus.DETECTED,
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident_id] = incident
        return incident

    def get(self, incident_id: str) -> Incident:
        try:
            return self._incidents[incident_id]
        except KeyError as exc:
            raise IncidentNotFoundError(incident_id) from exc

    def update_status(self, incident_id: str, status: IncidentStatus) -> Incident:
        incident = self.get(incident_id)
        updated = incident.model_copy(update={"status": status, "updated_at": datetime.now(UTC)})
        self._incidents[incident_id] = updated
        return updated

    def list_for_device(self, device_id: str) -> list[Incident]:
        """Prior incidents on the same device -- what the Threat Reasoning
        Agent's `get_incident`-family tool call uses for propagation context
        (Section 11's agent table)."""
        return [incident for incident in self._incidents.values() if incident.device_id == device_id]

    def list_all(self) -> list[Incident]:
        return list(self._incidents.values())


def _incident_from_row(row: IncidentORM) -> Incident:
    return Incident(
        incident_id=row.incident_id,
        device_id=row.device_id,
        status=IncidentStatus(row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        chain_tx_id=row.chain_tx_id,
    )


class PostgresIncidentRepository:
    """Real, Postgres-backed `IncidentRepository` -- same public interface,
    same synchronous call shape (see `app/core/db.py`'s docstring for why
    sync), backed by the `incidents` table (`app/models/orm.py`) instead of
    a dict. One short-lived session per call (`session_scope`), not one
    session held for the repository's lifetime, so concurrent requests each
    get their own transaction rather than contending on a shared one.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create(self, incident_id: str, device_id: str) -> Incident:
        now = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            if session.get(IncidentORM, incident_id) is not None:
                raise ValueError(f"Incident '{incident_id}' already exists")
            row = IncidentORM(
                incident_id=incident_id,
                device_id=device_id,
                status=IncidentStatus.DETECTED.value,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            return _incident_from_row(row)

    def get(self, incident_id: str) -> Incident:
        with session_scope(self._session_factory) as session:
            row = session.get(IncidentORM, incident_id)
            if row is None:
                raise IncidentNotFoundError(incident_id)
            return _incident_from_row(row)

    def update_status(self, incident_id: str, status: IncidentStatus) -> Incident:
        with session_scope(self._session_factory) as session:
            row = session.get(IncidentORM, incident_id)
            if row is None:
                raise IncidentNotFoundError(incident_id)
            row.status = status.value
            row.updated_at = datetime.now(UTC)
            session.flush()
            return _incident_from_row(row)

    def list_for_device(self, device_id: str) -> list[Incident]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(IncidentORM)
                .filter(IncidentORM.device_id == device_id)
                .all()
            )
            return [_incident_from_row(row) for row in rows]

    def list_all(self) -> list[Incident]:
        with session_scope(self._session_factory) as session:
            rows = session.query(IncidentORM).all()
            return [_incident_from_row(row) for row in rows]
