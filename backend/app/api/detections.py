"""`/detections` — run a scenario against the simulator and score it.

Phase 3 scope, concretely: there is no live, always-on polling loop yet (that
is a Phase 9+ concern once there's a persistent event store to poll -- see
Section 8's storage strategy, which still has telemetry/events living only in
memory via the ScenarioRunner at this phase). What *is* real here: given a
scripted scenario, run it against the live device registry exactly the way
Phase 2's tests do, extract features from the resulting event stream per
device, and score them with a real trained model artifact -- this is "the
detection engine scores the event stream" from Section 7, step 3, done
on-demand rather than continuously. A later phase can call this same scoring
path from a scheduler without changing it.

No model artifact ships in the repo (gitignored per Section 8 -- trained
artifacts don't belong in git). If none has been trained yet in this
environment, this router returns 503 with instructions, rather than crashing
app startup or silently returning no detections as if that were a real
result.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from app.cybersecurity.detection_service import DetectionService, load_model
from app.cybersecurity.feature_extraction import FeatureWindow
from app.iomt_simulator.hospital import build_default_fleet
from app.iomt_simulator.scenario import AttackInjection, ScenarioRunner
from app.schemas.detection import DetectionEvent

router = APIRouter(prefix="/detections", tags=["detections"])

_DEFAULT_MODEL_PATH = Path("experiments/models/random_forest.joblib")

# Process-wide cache so each request doesn't re-load+re-deserialize the
# model artifact from disk; invalidated only by process restart, consistent
# with "retraining is a deliberate, versioned step" (Section 10) -- this
# service never hot-reloads a model out from under itself mid-process.
_service_cache: DetectionService | None = None


def get_detection_service() -> DetectionService:
    global _service_cache
    if _service_cache is None:
        try:
            model = load_model(_DEFAULT_MODEL_PATH)
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No trained detection model is available. Train one first: "
                    "cd backend && python -m app.cybersecurity.training "
                    f"(expected artifact at {_DEFAULT_MODEL_PATH})."
                ),
            ) from exc
        _service_cache = DetectionService(model)
    return _service_cache


@router.post("/run-scenario", response_model=list[DetectionEvent])
async def run_scenario_and_detect(
    service: DetectionService = Depends(get_detection_service),
) -> list[DetectionEvent]:
    """Run one fixed, reproducible attack scenario (a scripted spoofed-command
    injection against the ventilator, same shape as the Phase 2 scenario
    tests) and return whatever the loaded model detects from it.

    This is deliberately a fixed built-in scenario, not an arbitrary
    user-supplied one -- Phase 3 has no scenario-authoring API yet (Section 17
    and 18's named scenarios are still hand-defined in test/experiment code),
    so exposing free-form scenario injection here would be building an
    unplanned feature rather than wiring up what Phase 3 actually specifies.
    """
    registry = build_default_fleet()
    injection = AttackInjection(
        tick=6,
        device_id="ventilator-01",
        event_type="spoofed_command",
        payload={"command": "set_tidal_volume", "value": "50"},
        device_effect=lambda device: device.set_network_state("compromised"),
    )
    runner = ScenarioRunner(registry, seed=42, injections=[injection])
    result = runner.run(num_ticks=10)

    detections: list[DetectionEvent] = []
    events_by_device: dict[str, list] = {}
    for event in result.network_events:
        events_by_device.setdefault(event.device_id, []).append(event)

    for device_id, events in events_by_device.items():
        window = FeatureWindow(
            device_id=device_id,
            window_start=events[0].timestamp,
            window_end=events[-1].timestamp,
            events=events,
        )
        detection = service.score_window(window)
        if detection is not None:
            detections.append(detection)

    return detections
