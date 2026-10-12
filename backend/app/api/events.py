"""`/events` — read-only view onto recorded network/security events.

Same reasoning and pattern as `app/api/telemetry.py`: `NetworkEventStore`
(Phase 4, `app/repositories/telemetry_events.py`) is the real in-memory
store the Investigation/Recovery Verification Agents' `get_network_events`
tool already reads from; `/detections/run-scenario` is what actually
writes into it. No write endpoint here -- events are produced by the
simulator/scenario runner, never injected by an API client directly.
"""

from fastapi import APIRouter, Depends

from app.api.dependencies import get_network_event_store
from app.repositories.telemetry_events import NetworkEventStore
from app.schemas.events import NetworkEvent

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[NetworkEvent])
async def list_events(
    device_id: str | None = None, store: NetworkEventStore = Depends(get_network_event_store)
) -> list[NetworkEvent]:
    """Every network/security event recorded so far, optionally filtered to
    one device. Returns an empty list, never a fabricated event, when
    nothing has been recorded yet for the given filter."""
    return store.query(device_id=device_id)
