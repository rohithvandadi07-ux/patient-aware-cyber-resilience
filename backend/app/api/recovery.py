"""`/recovery` — L8 Recovery Orchestrator, over HTTP (architecture spec
Section 7 step 12 / Section 4's dashed loop).

`POST` wraps `RecoveryOrchestrator.process_result` (Phase 7,
`app/recovery/engine.py`, 100% measured branch coverage): takes a
`RecoveryResult` (the Recovery Verification Agent's structured finding --
this router does not call the agent itself, same reasoning as
`/risk-assessments`: no real LLM backend or orchestration layer exists yet
to produce one automatically), records it as evidence, and transitions the
incident to `RESOLVED` or `REOPENED`. Also enqueues the recovery's
blockchain provenance (step 13) once processed.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import (
    get_outbox_repository,
    get_recovery_orchestrator,
    get_recovery_result_repository,
)
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_recovery
from app.recovery.engine import InconsistentRecoveryResultError, RecoveryOrchestrator
from app.repositories.incidents import IncidentNotFoundError
from app.repositories.recovery_results import RecoveryResultRepository
from app.schemas.agents import RecoveryResult
from app.schemas.blockchain import RecoveryProvenance
from app.schemas.incident import Incident

router = APIRouter(prefix="/recovery", tags=["recovery"])


@router.post("", response_model=Incident)
async def process_recovery_result(
    result: RecoveryResult,
    orchestrator: RecoveryOrchestrator = Depends(get_recovery_orchestrator),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
) -> Incident:
    try:
        incident = orchestrator.process_result(result)
    except IncidentNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=f"Incident '{result.incident_id}' not found"
        ) from exc
    except InconsistentRecoveryResultError as exc:
        # The evidence was still recorded (process_result's own contract --
        # see its docstring) even though routing was refused; 409 reflects
        # "understood, evidence kept, but the incident state could not be
        # decided," not a request error.
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    enqueue_recovery(
        outbox_repo,
        RecoveryProvenance(
            incident_id=result.incident_id,
            recovery_verified=result.recovery_succeeded,
            residual_threats_hash=hash_payload(result.residual_threats)
            if result.residual_threats
            else None,
        ),
    )
    return incident


@router.get("", response_model=list[RecoveryResult])
async def list_recovery_results(
    repo: RecoveryResultRepository = Depends(get_recovery_result_repository),
) -> list[RecoveryResult]:
    return repo.list_all()


@router.get("/{incident_id}", response_model=list[RecoveryResult])
async def list_recovery_results_for_incident(
    incident_id: str, repo: RecoveryResultRepository = Depends(get_recovery_result_repository)
) -> list[RecoveryResult]:
    return repo.list_for_incident(incident_id)
