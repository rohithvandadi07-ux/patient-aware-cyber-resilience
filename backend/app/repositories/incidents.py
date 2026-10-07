"""In-memory Incident repository.

Architecture spec Section 8: incidents eventually live in PostgreSQL, with
foreign keys enforcing that an incident always references a real device --
but that's Phase 9 (backend integration/persistence). Every layer from Phase 4
onward (agents, risk engine, policy engine) needs *some* real incident store to
call `get_incident`/create/update against now, so this repository holds that
contract today as an in-memory dict, following the same pattern as Phase 2's
`DeviceRegistry` -- swapping this for a real Postgres-backed implementation in
Phase 9 should be a constructor change for callers, not an API rewrite, which
is why the public methods here are already shaped like repository methods
(`get`, `create`, `update_status`), not like dict access.
"""

from datetime import UTC, datetime

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
