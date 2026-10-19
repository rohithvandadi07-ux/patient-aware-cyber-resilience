"""`/patients` -- read-only view of the synthetic patients, plus a demo clock control.

The clock advance is a simulation control for demos (it moves simulated time so a
patient's vitals evolve); it does not touch devices or incidents.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.dependencies import get_patient_registry
from app.iomt_simulator.patients import PatientNotFoundError, PatientRegistry
from app.schemas.patient import PatientState

router = APIRouter(prefix="/patients", tags=["patients"])


class ClockAdvanceRequest(BaseModel):
    minutes: int = Field(gt=0, le=1440)


class ClockState(BaseModel):
    simulated_minute: int


@router.get("", response_model=list[PatientState])
async def list_patients(registry: PatientRegistry = Depends(get_patient_registry)) -> list[PatientState]:
    return registry.list_patients()


@router.post("/clock/advance", response_model=ClockState)
async def advance_clock(
    body: ClockAdvanceRequest, registry: PatientRegistry = Depends(get_patient_registry)
) -> ClockState:
    return ClockState(simulated_minute=registry.advance(body.minutes))


@router.get("/{patient_id}", response_model=PatientState)
async def get_patient(
    patient_id: str, registry: PatientRegistry = Depends(get_patient_registry)
) -> PatientState:
    try:
        return registry.get_patient_state(patient_id)
    except PatientNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Patient '{patient_id}' not found") from exc