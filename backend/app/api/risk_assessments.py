"""`/risk-assessments` — L5, the patient-aware dual-risk engine, over HTTP.

Architecture spec Section 7 step 7: the Risk Engine "takes the
`ThreatAssessment` and `ClinicalContext` and calls `calculate_risk(...)`,
returning a `RiskScore`." This router is a thin wrapper over
`RuleBasedRiskModel.calculate_risk` (Phase 5, `app/risk_engine/rule_based.py`,
100% measured branch coverage) -- no new scoring logic lives here.

Stateless and unpersisted, deliberately: Section 8's storage table does not
name a `risk_assessments`/`RiskScore` table anywhere (only incidents,
decisions, approvals, responses, recoveries, and the outbox are listed), and
a `RiskScore` only feeds the next step (the Policy Engine via
`/responses/proposed`) -- it is not itself one of the five Section 14
blockchain-provenance event types. Persisting it here would be inventing a
store the architecture doc never asked for.

Why this takes `ThreatAssessment`/`ClinicalContext`/`candidate_responses`
directly as request body fields, rather than looking an incident up by id
internally: no orchestration layer sequences the five agents automatically
yet (`app/agents/README.md`'s own "known gaps" section), so there is no
agent-produced `ThreatAssessment`/`ClinicalContext` sitting in a repository
this endpoint could fetch -- the caller (today, a test; eventually whatever
later phase builds the real multi-agent pipeline) supplies them directly,
the same literal input shape Section 12 specifies.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.risk import RiskScore

router = APIRouter(prefix="/risk-assessments", tags=["risk-assessments"])

_model = RuleBasedRiskModel()


class RiskAssessmentRequest(BaseModel):
    threat: ThreatAssessment
    context: ClinicalContext
    candidate_responses: list[CandidateAction]


@router.post("", response_model=RiskScore)
async def calculate_risk(body: RiskAssessmentRequest) -> RiskScore:
    """Raises 400 on `RuleBasedRiskModel.calculate_risk`'s own `ValueError`s:
    an empty `candidate_responses` list, or a `threat`/`context` incident_id
    mismatch -- never silently guesses which incident to score."""
    try:
        return _model.calculate_risk(body.threat, body.context, body.candidate_responses)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
