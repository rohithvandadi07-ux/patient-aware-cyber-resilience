"""Response Planning Agent (L4, fourth of the five).

Architecture spec Section 11: input `ThreatAssessment`, `ClinicalContext`,
`RiskScore`; tool `evaluate_policy` (read-only check, not execution --
"would this be auto-approved"); output `ProposedResponse {candidate_actions,
security_benefit, clinical_impact, recommended_action, rationale}`.

**No execute capability, structurally enforced:** this module calls no
execution tool anywhere -- `AgentToolkit` has no `execute_*` method for any
agent to call (see `app/agents/tools.py`), and `ProposedResponse` itself has
no field or method that triggers an action. Only the Policy Engine (L6,
Phase 6) and, downstream of it, the Response Orchestrator (L7, Phase 6/7) can
turn this proposal into an executed action.

**RiskScore dependency note:** Section 11 lists `RiskScore` as an input, but
the Risk Engine that produces it (Section 12) is Phase 5 work, not built yet.
This agent's signature takes `risk_score: RiskScore | None` for that reason --
`None` until Phase 5 exists, never a fabricated placeholder RiskScore. The
prompt says plainly when risk-score data is unavailable rather than silently
treating "no risk score" the same as "zero risk."

**evaluate_policy note (updated for Phase 6):** `AgentToolkit.evaluate_policy`
now wires to the real Policy Engine (L6). This agent calls it only when it
already has a real `risk_score` -- the Policy Engine routes on
response_impact, so there is nothing to evaluate without one. When
`risk_score` is `None` (Phase 5 not yet in the loop for this call, or the
Risk Engine genuinely has nothing yet), the prompt says so honestly rather
than skipping the note silently or treating "no risk score" as "policy
check unavailable" for an unrelated reason. When a real `risk_score` is
available, the prompt is told, per scored candidate action, whether the
Policy Engine would require human approval and which `policy_rule_id`
produced that -- a real pre-check, not a placeholder.
"""

import json

from app.agents.base import run_agent_call
from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.schemas.agents import ClinicalContext, ProposedResponse, ThreatAssessment
from app.schemas.enums import IncidentStatus
from app.schemas.risk import RiskScore

_AGENT_NAME = "response_planning"


def _try_evaluate_policy(
    toolkit: AgentToolkit, risk_score: RiskScore | None, context: ClinicalContext
) -> str:
    if risk_score is None:
        return (
            "not available: no RiskScore provided yet -- do not assume auto-approval or "
            "rejection either way"
        )
    decisions = toolkit.evaluate_policy(risk_score, context)
    if not decisions:
        return (
            "not available: risk_score has no scored candidate actions yet -- do not assume "
            "auto-approval or rejection either way"
        )
    per_action = "; ".join(
        f"{action}: "
        f"{'requires human approval' if decision.requires_human_approval else 'autonomous OK'} "
        f"(rule={decision.policy_rule_id})"
        for action, decision in sorted(decisions.items())
    )
    return f"Policy Engine pre-check per scored candidate action -- {per_action}"


def _build_prompt(
    threat: ThreatAssessment, context: ClinicalContext, risk_score: RiskScore | None, policy_note: str
) -> str:
    payload = {
        "threat_assessment": threat.model_dump(mode="json"),
        "clinical_context": context.model_dump(mode="json"),
        "risk_score": risk_score.model_dump(mode="json") if risk_score is not None else None,
        "policy_pre_check": policy_note,
    }
    return (
        "You are the Response Planning Agent for a healthcare IoMT cyber-resilience "
        "system. Given the threat assessment, clinical context, and (if available) "
        "risk score below, produce a JSON object matching this schema: "
        f"{json.dumps(ProposedResponse.model_json_schema())}\n\n"
        "Rules: you have no execute capability -- `recommended_action` and "
        "`rationale` are a proposal only; the Policy Engine and Response "
        "Orchestrator decide if and how it is actually carried out. Weigh "
        "`clinical_impact` seriously: a device with patient_dependency=true and "
        "high criticality means even a well-justified security action (e.g. "
        "shutdown) may be clinically unacceptable regardless of threat severity -- "
        "this is the 'most secure cyber response is not always the safest clinical "
        f"response' principle. If `risk_score` is null, say so in `rationale` "
        "rather than assuming risk is low.\n\n"
        f"Data:\n{json.dumps(payload, default=str)}"
    )


def plan_response(
    client: LLMClient,
    toolkit: AgentToolkit,
    threat: ThreatAssessment,
    context: ClinicalContext,
    risk_score: RiskScore | None = None,
) -> ProposedResponse:
    """Run the Response Planning Agent.

    Raises `AgentStalledError` and marks the incident
    `RESPONSE_PLANNING_STALLED` if the LLM cannot produce a valid
    `ProposedResponse` after one retry.
    """
    policy_note = _try_evaluate_policy(toolkit, risk_score, context)
    prompt = _build_prompt(threat, context, risk_score, policy_note)
    return run_agent_call(
        client=client,
        toolkit=toolkit,
        agent_name=_AGENT_NAME,
        incident_id=threat.incident_id,
        prompt=prompt,
        output_schema=ProposedResponse,
        input_payload={
            "threat_assessment": threat.model_dump(mode="json"),
            "clinical_context": context.model_dump(mode="json"),
            "risk_score": risk_score.model_dump(mode="json") if risk_score is not None else None,
        },
        stall_status=IncidentStatus.RESPONSE_PLANNING_STALLED,
    )
