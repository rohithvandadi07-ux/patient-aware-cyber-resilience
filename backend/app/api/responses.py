"""`/responses/proposed` and `/responses/executed` — L6 Policy Engine routing
and L7 Response Orchestrator execution, over HTTP (architecture spec Section
7 steps 9-11).

`POST /responses/proposed` wraps `PolicyEngine.evaluate` (Phase 6,
`app/policy_engine/engine.py`, 100% measured branch coverage): given a
`RiskScore` + `ProposedResponse` + `ClinicalContext`, it returns the
`PolicyDecision` and -- new in Phase 9 -- holds it in
`ProposedResponseRepository` so a second request (step 10's "a human
approves or rejects" or step 11's autonomous execution) can act on it, and
enqueues the decision's blockchain provenance (step 13).

`POST /responses/executed` wraps `ResponseOrchestrator.execute` (Phase 6/7,
`app/response_engine/orchestrator.py`, 100% measured branch coverage)
against whichever `PolicyDecision` is pending for the given incident. This
is the one place in the whole API that can actually mutate a simulated
device's state -- exactly the structural guarantee that module's own
docstring states ("the only function anywhere in this codebase that calls a
`SimulatedDevice` mutation method on the strength of a `PolicyDecision`").
A successful execution records the `ExecutedResponse`, enqueues its (and,
if supplied, the approval's) blockchain provenance, and clears the now-stale
proposed decision.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.dependencies import (
    get_executed_response_repository,
    get_outbox_repository,
    get_policy_engine,
    get_proposed_response_repository,
    get_response_orchestrator,
)
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_approval, enqueue_decision, enqueue_response
from app.core.auth import Principal, get_current_principal, require_role
from app.iomt_simulator.registry import DeviceNotFoundError
from app.policy_engine.engine import PolicyEngine
from app.repositories.incidents import IncidentNotFoundError
from app.repositories.responses import (
    ExecutedResponseRepository,
    ProposedResponseNotFoundError,
    ProposedResponseRepository,
)
from app.response_engine.orchestrator import (
    ApprovalRequiredError,
    ResponseOrchestrator,
    ResponseRejectedError,
)
from app.schemas.agents import ClinicalContext, ProposedResponse
from app.schemas.blockchain import ApprovalProvenance, DecisionProvenance, ResponseProvenance
from app.schemas.policy import PolicyDecision
from app.schemas.response import ApprovalRecord, ExecutedResponse
from app.schemas.risk import RiskScore

router = APIRouter(prefix="/responses", tags=["responses"])


class ProposeResponseRequest(BaseModel):
    risk_score: RiskScore
    proposed_response: ProposedResponse
    context: ClinicalContext
    detection_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="The detector's confidence for this incident. Only consulted when the Policy "
        "Engine's opt-in confidence gate is enabled (Settings.policy_min_autonomous_confidence); "
        "with the gate on and this omitted, autonomy is not granted.",
    )


class ExecuteResponseRequest(BaseModel):
    incident_id: str
    approval: ApprovalRecord | None = None


@router.post("/proposed", response_model=PolicyDecision, status_code=201)
async def propose_response(
    body: ProposeResponseRequest,
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    proposed_repo: ProposedResponseRepository = Depends(get_proposed_response_repository),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
) -> PolicyDecision:
    try:
        decision = policy_engine.evaluate(
            body.risk_score, body.proposed_response, body.context, body.detection_confidence
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    proposed_repo.put(decision)
    enqueue_decision(
        outbox_repo,
        DecisionProvenance(
            incident_id=decision.incident_id,
            risk_score_hash=hash_payload(body.risk_score),
            policy_rule_id=decision.policy_rule_id,
            recommended_action=decision.chosen_action,
        ),
    )
    return decision


@router.get("/proposed", response_model=list[PolicyDecision])
async def list_proposed_responses(
    proposed_repo: ProposedResponseRepository = Depends(get_proposed_response_repository),
) -> list[PolicyDecision]:
    return proposed_repo.list_all()


@router.get("/proposed/{incident_id}", response_model=PolicyDecision)
async def get_proposed_response(
    incident_id: str,
    proposed_repo: ProposedResponseRepository = Depends(get_proposed_response_repository),
) -> PolicyDecision:
    try:
        return proposed_repo.get(incident_id)
    except ProposedResponseNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=f"No proposed response pending for incident {incident_id!r}"
        ) from exc


@router.post("/executed", response_model=ExecutedResponse, status_code=201)
async def execute_response(
    body: ExecuteResponseRequest,
    orchestrator: ResponseOrchestrator = Depends(get_response_orchestrator),
    proposed_repo: ProposedResponseRepository = Depends(get_proposed_response_repository),
    executed_repo: ExecutedResponseRepository = Depends(get_executed_response_repository),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
    principal: Principal = Depends(get_current_principal),
) -> ExecutedResponse:
    # Post-Phase-15: executing a response with a human approval attached is
    # the one HTTP action that can both mutate a simulated device's state
    # *and* carry someone's identity as having approved it -- require the
    # 'approver' role for that specific case. Auto-approved (requires_human_
    # approval=False) execution needs no approval body at all, so it stays
    # at the base 'operator' role the router-level dependency already
    # resolved (Settings.auth_enabled controls whether that check is live).
    if body.approval is not None:
        require_role(principal, "approver")

    try:
        decision = proposed_repo.get(body.incident_id)
    except ProposedResponseNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"No proposed response pending for incident {body.incident_id!r}",
        ) from exc

    try:
        executed = orchestrator.execute(decision, approval=body.approval)
    except ApprovalRequiredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ResponseRejectedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (IncidentNotFoundError, DeviceNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except NotImplementedError as exc:
        # A real, honest gap -- see orchestrator.py's module docstring: no
        # session/credential/backup/failover mechanism exists in the
        # simulator for four ResponseActionCategory values. 501, not 500:
        # the request was understood, the server genuinely cannot do it.
        raise HTTPException(status_code=501, detail=str(exc)) from exc

    executed_repo.record(executed)
    proposed_repo.remove(body.incident_id)

    enqueue_response(
        outbox_repo,
        ResponseProvenance(
            incident_id=executed.incident_id,
            action_taken=executed.action_taken,
            executed_by=executed.executed_by,
            timestamp=executed.timestamp,
        ),
    )
    if body.approval is not None:
        enqueue_approval(
            outbox_repo,
            ApprovalProvenance(
                incident_id=body.approval.incident_id,
                approver_identity=body.approval.approver_identity,
                decision=body.approval.decision,
                timestamp=body.approval.timestamp,
            ),
        )

    return executed


@router.get("/executed", response_model=list[ExecutedResponse])
async def list_executed_responses(
    executed_repo: ExecutedResponseRepository = Depends(get_executed_response_repository),
) -> list[ExecutedResponse]:
    return executed_repo.list_all()


@router.get("/executed/{incident_id}", response_model=list[ExecutedResponse])
async def list_executed_responses_for_incident(
    incident_id: str,
    executed_repo: ExecutedResponseRepository = Depends(get_executed_response_repository),
) -> list[ExecutedResponse]:
    return executed_repo.list_for_incident(incident_id)
