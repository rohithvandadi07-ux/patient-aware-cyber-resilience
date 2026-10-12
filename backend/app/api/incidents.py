"""`/incidents` — the Incident aggregate (architecture spec Section 7).

List/get is a thin read wrapper over `IncidentRepository` (Phase 4,
`app/repositories/incidents.py`), the same shape as `/devices`. `POST` is
new in Phase 9: Section 7 step 3 says a detection "creates an `Incident` in
`status=detected`" -- before this phase, nothing outside a test fixture
ever called `IncidentRepository.create`, so this endpoint (and
`/detections/run-scenario`'s own call into the same repository, see
`app/api/detections.py`) is what actually closes that gap for real,
instead of leaving "creates an Incident" as a sentence in a doc nothing
executes.

Creating an incident also enqueues its `IncidentProvenance` onto the
blockchain outbox (Section 7 step 13: "every state transition from step 3
onward ... is appended to the outbox table"; `app/blockchain/outbox.py`'s
own docstring names "the response orchestrator, recovery orchestrator,
policy engine, approval endpoint" as the intended callers of its
`enqueue_*` helpers -- this endpoint is that same intended wiring for the
incident step). The outbox entry stays `PENDING` until something drains it
(`/blockchain/audit`'s `process` endpoint, or a real deployment's
`OutboxWorker.run_forever()`) -- this endpoint does not block on that.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.dependencies import get_device_registry, get_incident_repository, get_outbox_repository
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_incident
from app.iomt_simulator.registry import DeviceNotFoundError, DeviceRegistry
from app.repositories.incidents import IncidentNotFoundError, IncidentRepository
from app.schemas.blockchain import IncidentProvenance
from app.schemas.enums import AttackCategory
from app.schemas.incident import Incident

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreateRequest(BaseModel):
    incident_id: str
    device_id: str
    attack_type: AttackCategory = Field(
        description="Carried through to the incident's blockchain provenance record -- not stored "
        "on the `Incident` schema itself (architecture spec Section 7's `Incident` has no "
        "attack_type field; that lives on the `DetectionEvent`/`ThreatAssessment` that led here)."
    )
    evidence_ref: str = Field(
        description="Reference to the underlying evidence (e.g. a `DetectionEvent.evidence_ref`), "
        "hashed before it crosses into the blockchain provenance record -- never stored raw "
        "on-chain (Section 14)."
    )
    timestamp: datetime


@router.get("", response_model=list[Incident])
async def list_incidents(repo: IncidentRepository = Depends(get_incident_repository)) -> list[Incident]:
    return repo.list_all()


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(
    incident_id: str, repo: IncidentRepository = Depends(get_incident_repository)
) -> Incident:
    try:
        return repo.get(incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found") from exc


@router.post("", response_model=Incident, status_code=201)
async def create_incident(
    body: IncidentCreateRequest,
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    device_registry: DeviceRegistry = Depends(get_device_registry),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
) -> Incident:
    try:
        device_registry.get_device_state(body.device_id)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=f"Device '{body.device_id}' not found"
        ) from exc

    try:
        incident = incident_repo.create(body.incident_id, device_id=body.device_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    provenance = IncidentProvenance(
        incident_id=incident.incident_id,
        device_id=incident.device_id,
        attack_type=body.attack_type.value,
        evidence_hash=hash_payload(body.evidence_ref),
        timestamp=body.timestamp,
    )
    enqueue_incident(outbox_repo, provenance)

    return incident
