"""`/telemetry` — read-only view onto recorded device telemetry.

Architecture spec Section 8: telemetry belongs in a TimescaleDB hypertable
at full scale -- that's deferred persistence work, not this phase's gate
(Section 19: "all resource routers from Section 15 exist and are covered by
API tests"). What's real right now: `TelemetryStore` (Phase 4,
`app/repositories/telemetry_events.py`) is the actual in-memory store the
Investigation Agent's `get_telemetry` tool already reads from, and
`/detections/run-scenario` (Phase 9, see `app/api/detections.py`) is what
actually writes into it -- running a scenario, then calling this endpoint,
returns genuinely recorded readings, not a fabricated response shape with
nothing behind it.

No write endpoint here, matching `/devices`' own reasoning: telemetry is
produced by the simulator/scenario runner, never injected by an API client
directly.
"""

from fastapi import APIRouter, Depends

from app.api.dependencies import get_telemetry_store
from app.repositories.telemetry_events import TelemetryStore
from app.schemas.telemetry import TelemetryReading

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("", response_model=list[TelemetryReading])
async def list_telemetry(
    device_id: str | None = None, store: TelemetryStore = Depends(get_telemetry_store)
) -> list[TelemetryReading]:
    """Every telemetry reading recorded so far, optionally filtered to one
    device. Returns an empty list, never a fabricated reading, when nothing
    has been recorded yet for the given filter."""
    return store.query(device_id=device_id)
