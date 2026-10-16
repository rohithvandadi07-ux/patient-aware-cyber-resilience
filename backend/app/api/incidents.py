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

from app.api.dependencies import (
    get_agent_trace_recorder,
    get_device_registry,
    get_incident_orchestrator,
    get_incident_repository,
    get_network_event_store,
    get_outbox_repository,
    get_recovery_result_repository,
    get_telemetry_store,
)
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_incident
from app.core.auth import Principal, get_current_principal, require_role
from app.iomt_simulator.registry import DeviceNotFoundError, DeviceRegistry
from app.orchestration.orchestrator import CycleResult, IncidentOrchestrator
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentNotFoundError, IncidentRepository
from app.repositories.recovery_results import RecoveryResultRepository
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.blockchain import IncidentProvenance
from app.schemas.enums import AttackCategory
from app.schemas.incident import Incident
from app.schemas.policy import PolicyDecision
from app.schemas.response import ExecutedResponse

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


class InvestigateRequest(BaseModel):
    auto_approve: bool = Field(
        default=False,
        description="If true and the Policy Engine requires human approval, the orchestrator "
        "fabricates an auto-approval record (approver_identity='orchestrator-auto-approve') "
        "instead of stopping -- intended for automated research/evaluation runs with no human in "
        "the loop, never for a real deployment. Default false: the real caller-in-the-loop path.",
    )


class CycleResultOut(BaseModel):
    """`CycleResult` (`app/orchestration/orchestrator.py`), re-shaped as the
    API's response schema. `history` is a human-readable step trace --
    the same evidence `GET /agents/{incident_id}` shows structurally, just
    summarized in call order for a quick status check."""

    incident_id: str
    final_status: str
    reinvestigation_count: int
    history: list[str]
    awaiting_approval_decision: PolicyDecision | None = None
    executed: ExecutedResponse | None = None
    stage_timings_ms: dict[str, float] = {}

    @classmethod
    def from_cycle_result(cls, result: CycleResult) -> "CycleResultOut":
        return cls(
            incident_id=result.incident_id,
            final_status=result.final_status,
            reinvestigation_count=result.reinvestigation_count,
            history=result.history,
            awaiting_approval_decision=result.awaiting_approval_decision,
            executed=result.executed,
            stage_timings_ms=result.stage_timings_ms,
        )


@router.post("/{incident_id}/investigate", response_model=CycleResultOut)
async def investigate_incident(
    incident_id: str,
    body: InvestigateRequest = InvestigateRequest(),
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    orchestrator: IncidentOrchestrator = Depends(get_incident_orchestrator),
    principal: Principal = Depends(get_current_principal),
) -> CycleResultOut:
    """Runs the real multi-agent pipeline (`IncidentOrchestrator`,
    post-Phase-15) for this incident end to end: investigate -> threat
    reasoning -> healthcare context -> response planning -> risk scoring ->
    policy decision -> (approval gate) -> execution -> recovery
    verification -> recovery routing, re-investigating automatically (up to
    a bounded budget) if recovery routes to `REOPENED`.

    This is the real backend for the architecture plan's `/incidents/{id}/
    investigate` endpoint -- previously absent (see `claude/
    architecture-decisions.md`'s Post-Phase-15 gap audit: "no orchestration
    layer sequences the five agents automatically yet"). Which concrete
    `LLMClient` it calls through depends entirely on `Settings.llm_backend`
    (`app/core/app_factory.py`) -- `MockLLMClient` by default, so calling
    this endpoint without a configured `GEMINI_API_KEY` will stall on the
    very first agent call (`MockLLMClient` with no scripted responses raises
    immediately) rather than silently fabricating a result. That is the
    correct, honest behavior for the default configuration, not a bug.
    """
    # Post-Phase-15: auto_approve=True lets this single call both execute a
    # response AND fabricate the approval behind it -- the same sensitivity
    # as a human-supplied approval on /responses/executed, so it needs the
    # same 'approver' role.
    if body.auto_approve:
        require_role(principal, "approver")

    try:
        incident = incident_repo.get(incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found") from exc

    try:
        result = orchestrator.run_investigation_cycle(
            incident_id, incident.device_id, auto_approve=body.auto_approve
        )
    except RuntimeError as exc:
        # The real, honest failure mode when `Settings.llm_backend` is
        # "mock" (the default) with no scripted responses, or when a real
        # `GeminiLLMClient` call genuinely fails (bad key, network, rate
        # limit) -- both `MockLLMClient.generate` and `GeminiLLMClient.
        # generate` raise `RuntimeError` for exactly this reason (see
        # `app/agents/llm_client.py`). 503, not 500: the request was
        # understood, the server just has no working LLM backend to serve
        # it with right now.
        raise HTTPException(status_code=503, detail=f"LLM backend call failed: {exc}") from exc
    return CycleResultOut.from_cycle_result(result)


class IncidentEvidence(BaseModel):
    """Consolidated real evidence for one incident -- the architecture
    plan's `/incidents/{id}/evidence` endpoint. Every field is a real,
    already-recorded read (agent traces, network events and telemetry for
    the incident's device, recovery results) -- nothing here is computed or
    fabricated for this response; it is a join over four existing
    repositories/stores, keyed by this incident and its device."""

    incident_id: str
    device_id: str
    agent_traces: list[dict]
    network_events: list[dict]
    telemetry: list[dict]
    recovery_results: list[dict]


@router.get("/{incident_id}/evidence", response_model=IncidentEvidence)
async def get_incident_evidence(
    incident_id: str,
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    trace_recorder: AgentTraceRecorder = Depends(get_agent_trace_recorder),
    network_event_store: NetworkEventStore = Depends(get_network_event_store),
    telemetry_store: TelemetryStore = Depends(get_telemetry_store),
    recovery_repo: RecoveryResultRepository = Depends(get_recovery_result_repository),
) -> IncidentEvidence:
    try:
        incident = incident_repo.get(incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found") from exc

    return IncidentEvidence(
        incident_id=incident_id,
        device_id=incident.device_id,
        agent_traces=[
            {
                "agent_name": t.agent_name,
                "succeeded": t.succeeded,
                "recorded_at": t.recorded_at.isoformat(),
                "output_payload": t.output_payload,
                "error": t.error,
            }
            for t in trace_recorder.list_for_incident(incident_id)
        ],
        network_events=[
            e.model_dump(mode="json") for e in network_event_store.query(device_id=incident.device_id)
        ],
        telemetry=[
            r.model_dump(mode="json") for r in telemetry_store.query(device_id=incident.device_id)
        ],
        recovery_results=[r.model_dump(mode="json") for r in recovery_repo.list_for_incident(incident_id)],
    )
