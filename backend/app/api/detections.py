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

Phase 9 addition: Section 7 step 2 ("the collector timestamps and stores
[telemetry/events]") and step 3 ("this creates an `Incident` in
`status=detected`") were, before this phase, true only of the dedicated
test suites for each layer -- nothing on the request path actually wrote a
scenario's telemetry/events into the stores `/telemetry`/`/events` read
from (`app/repositories/telemetry_events.py`), or turned a `DetectionEvent`
into a real, queryable `Incident`. This endpoint now does both, using the
shared `app.state` singletons (not a second, disconnected copy), and
enqueues each new incident's blockchain provenance the same way
`/incidents`' own `POST` does. The scenario still runs against a *fresh*
`build_default_fleet()` registry, not `app.state.device_registry` --
deliberately preserved from Phase 3, so this fixed, scripted scenario
remains reproducible call-to-call regardless of what the shared device
registry's live state happens to be; only the resulting evidence (events,
telemetry, incidents, outbox entries) is written into shared state.
"""

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.dependencies import (
    get_incident_repository,
    get_network_event_store,
    get_outbox_repository,
    get_telemetry_store,
)
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_incident
from app.core.config import Settings, get_settings
from app.cybersecurity.detection_service import DetectionService, load_model
from app.cybersecurity.feature_extraction import FeatureWindow
from app.cybersecurity.real_flow_detection import InvalidFlowError, RealFlowDetectionService
from app.iomt_simulator.hospital import build_default_fleet
from app.iomt_simulator.scenario import AttackInjection, ScenarioRunner
from app.repositories.incidents import IncidentRepository
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.blockchain import IncidentProvenance
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
    network_event_store: NetworkEventStore = Depends(get_network_event_store),
    telemetry_store: TelemetryStore = Depends(get_telemetry_store),
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
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

    # Section 7 step 2: the collector stores telemetry/events, tagged with
    # device_id -- the shared stores, not a value nothing keeps.
    network_event_store.record_many(result.network_events)
    telemetry_store.record_many(result.telemetry)

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

    # Section 7 step 3: "This creates an Incident in status=detected" --
    # plus its blockchain provenance (step 13), same wiring as
    # /incidents' own POST. A fresh incident_id per detection (not a
    # device-derived one) because run-scenario can legitimately fire more
    # than once for the same device across the life of this process, and
    # IncidentRepository.create rejects a duplicate id outright.
    for detection in detections:
        incident_id = f"INC-{detection.device_id}-{uuid4().hex[:8]}"
        incident = incident_repo.create(incident_id, device_id=detection.device_id)
        provenance = IncidentProvenance(
            incident_id=incident.incident_id,
            device_id=incident.device_id,
            attack_type=detection.attack_type.value,
            evidence_hash=hash_payload(detection.evidence_ref),
            timestamp=detection.timestamp,
        )
        enqueue_incident(outbox_repo, provenance)

    return detections


# ---------------------------------------------------------------- real flows

_real_service_cache: dict[str, RealFlowDetectionService] = {}


def get_real_flow_service(settings: Settings = Depends(get_settings)) -> RealFlowDetectionService:
    """The real 45-feature CICIoMT2024 detector, cached per model path (same
    never-hot-reload rule as the proxy detector). 503 with training
    instructions if the (gitignored) artifact has not been produced."""
    path = settings.real_detector_model_path
    service = _real_service_cache.get(path)
    if service is None:
        try:
            service = RealFlowDetectionService.from_artifact(Path(path))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        _real_service_cache[path] = service
    return service


class FlowBatchRequest(BaseModel):
    """Flow records as emitted by a CICFlowMeter-style sensor: each flow is an
    object holding all 45 CICIoMT2024 feature values by their dataset column
    names (including the dataset's own spelling "Magnitue")."""

    device_id: str = Field(min_length=1)
    timestamp: datetime | None = None
    flows: list[dict[str, float]] = Field(min_length=1, max_length=1000)


class FlowVerdict(BaseModel):
    flow_index: int
    predicted_class: str
    family: str
    confidence: float
    detection: DetectionEvent | None


class FlowBatchResponse(BaseModel):
    model_name: str
    confidence_threshold: float
    verdicts: list[FlowVerdict]
    incident_ids: list[str] = Field(
        description="One incident per distinct attack type detected in the batch, opened from "
        "that type's most confident detection -- a 1000-flow flood opens one incident, not 1000."
    )


@router.post("/score-flows", response_model=FlowBatchResponse)
async def score_flows(
    request: FlowBatchRequest,
    service: RealFlowDetectionService = Depends(get_real_flow_service),
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
) -> FlowBatchResponse:
    """Score real flow-feature vectors with the real 19-class detector and open
    an incident (with blockchain provenance) for each distinct attack type it
    detects. Returns every flow's verdict, benign ones included, so the caller
    sees what was NOT flagged too."""
    try:
        results = service.score_flows(request.device_id, request.flows, request.timestamp)
    except InvalidFlowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    best_by_type: dict[str, DetectionEvent] = {}
    for result in results:
        d = result.detection
        if d is not None and (
            d.attack_type.value not in best_by_type
            or d.confidence > best_by_type[d.attack_type.value].confidence
        ):
            best_by_type[d.attack_type.value] = d

    incident_ids: list[str] = []
    for detection in best_by_type.values():
        incident_id = f"INC-{detection.device_id}-{uuid4().hex[:8]}"
        incident = incident_repo.create(incident_id, device_id=detection.device_id)
        enqueue_incident(
            outbox_repo,
            IncidentProvenance(
                incident_id=incident.incident_id,
                device_id=incident.device_id,
                attack_type=detection.attack_type.value,
                evidence_hash=hash_payload(detection.evidence_ref),
                timestamp=detection.timestamp,
            ),
        )
        incident_ids.append(incident.incident_id)

    return FlowBatchResponse(
        model_name=service.model_name,
        confidence_threshold=service.confidence_threshold,
        verdicts=[
            FlowVerdict(
                flow_index=r.flow_index,
                predicted_class=r.predicted_class,
                family=r.family,
                confidence=r.confidence,
                detection=r.detection,
            )
            for r in results
        ],
        incident_ids=incident_ids,
    )
