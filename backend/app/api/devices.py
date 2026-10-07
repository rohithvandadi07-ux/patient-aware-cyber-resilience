"""`/devices` — read-only view onto the simulated device fleet.

Phase 2 scope: list devices and read one device's current state. No write
endpoints here — device state changes only through the simulator/scenario
runner (Phase 2) and, later, the Response Orchestrator (Phase 6); the API layer
does not mutate device state directly.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_device_registry
from app.iomt_simulator.registry import DeviceNotFoundError, DeviceRegistry
from app.schemas.device import DeviceState

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceState])
async def list_devices(registry: DeviceRegistry = Depends(get_device_registry)) -> list[DeviceState]:
    return registry.list_devices()


@router.get("/{device_id}", response_model=DeviceState)
async def get_device(
    device_id: str, registry: DeviceRegistry = Depends(get_device_registry)
) -> DeviceState:
    try:
        return registry.get_device_state(device_id)
    except DeviceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found") from exc
