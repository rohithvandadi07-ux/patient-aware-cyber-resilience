"""Threat Reasoning Agent (L4, second of the five).

Architecture spec Section 11: input `InvestigationReport`; tool `get_incident`
(prior incidents on same device, for propagation context); output
`ThreatAssessment {attack_type, severity, confidence, propagation_risk,
reasoning_summary}`. `reasoning_summary` is explicitly interpretation, never
observed fact (Section 26) -- the agent reasons over the Investigation Agent's
report, it does not re-fetch raw evidence itself.
"""

import json

from app.agents.base import run_agent_call
from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.schemas.agents import InvestigationReport, ThreatAssessment
from app.schemas.enums import IncidentStatus

_AGENT_NAME = "threat_reasoning"


def _build_prompt(report: InvestigationReport, device_id: str, toolkit: AgentToolkit) -> str:
    prior_incidents = toolkit.get_prior_incidents_for_device(device_id)
    # Exclude this same incident from its own propagation context -- it is
    # the thing being assessed, not a prior incident informing the assessment.
    prior_incidents = [i for i in prior_incidents if i.incident_id != report.incident_id]

    payload = {
        "investigation_report": report.model_dump(mode="json"),
        "prior_incidents_on_device": [i.model_dump(mode="json") for i in prior_incidents],
    }

    return (
        "You are the Threat Reasoning Agent for a healthcare IoMT cyber-resilience "
        "system. Given the Investigation Agent's report and this device's incident "
        "history below, produce a JSON object matching this schema: "
        f"{json.dumps(ThreatAssessment.model_json_schema())}\n\n"
        "Rules: base `attack_type`, `severity`, and `confidence` on the investigation "
        "report's evidence and observations. `propagation_risk` should account for "
        "prior incidents on this same device, if any -- repeated incidents on one "
        "device raise propagation/recurrence concern. `reasoning_summary` is your "
        "interpretation, not a restatement of raw evidence.\n\n"
        f"Data:\n{json.dumps(payload, default=str)}"
    )


def assess_threat(
    client: LLMClient, toolkit: AgentToolkit, report: InvestigationReport, device_id: str
) -> ThreatAssessment:
    """Run the Threat Reasoning Agent against an Investigation Agent report.

    Raises `AgentStalledError` and marks the incident
    `THREAT_REASONING_STALLED` if the LLM cannot produce a valid
    `ThreatAssessment` after one retry.
    """
    prompt = _build_prompt(report, device_id, toolkit)
    return run_agent_call(
        client=client,
        toolkit=toolkit,
        agent_name=_AGENT_NAME,
        incident_id=report.incident_id,
        prompt=prompt,
        output_schema=ThreatAssessment,
        input_payload={"investigation_report": report.model_dump(mode="json"), "device_id": device_id},
        stall_status=IncidentStatus.THREAT_REASONING_STALLED,
    )
