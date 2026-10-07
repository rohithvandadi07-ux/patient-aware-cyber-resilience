"""Investigation Agent (L4, first of the five).

Architecture spec Section 11: input `incident_id`; tools `get_logs`,
`get_network_events`, `get_telemetry`, `get_device_state`; output
`InvestigationReport {evidence, timeline, affected_devices, observations,
confidence}`. Section 26 (via the schema's own field names): `evidence` is
observed fact only, `observations` is the investigator's interpretation of
that evidence -- distinct fields, never conflated.

This agent holds no execute capability and no write access to anything except
its own trace -- it reads through `AgentToolkit` and calls an `LLMClient`; it
never mutates device state, incident status (beyond the stall path inherited
from `run_agent_call`), or anything else.
"""

import json

from app.agents.base import run_agent_call
from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.schemas.agents import InvestigationReport
from app.schemas.enums import IncidentStatus

_AGENT_NAME = "investigation"


def _build_prompt(incident_id: str, device_id: str, toolkit: AgentToolkit) -> str:
    """Builds the prompt from real tool-fetched evidence only -- every value
    interpolated below came from an `AgentToolkit` call, never invented."""
    device_state = toolkit.get_device_state(device_id)
    network_events = toolkit.get_network_events(device_id)
    telemetry = toolkit.get_telemetry(device_id)
    logs = toolkit.get_logs(device_id=device_id, incident_id=incident_id)

    evidence_payload = {
        "incident_id": incident_id,
        "device_state": device_state.model_dump(mode="json"),
        "network_events": [e.model_dump(mode="json") for e in network_events],
        "telemetry": [t.model_dump(mode="json") for t in telemetry],
        "logs": [
            {"timestamp": r.timestamp.isoformat(), "level": r.level, "message": r.message} for r in logs
        ],
    }

    return (
        "You are the Investigation Agent for a healthcare IoMT cyber-resilience "
        "system. Given the evidence below for one incident, produce a JSON object "
        "matching this schema: "
        f"{json.dumps(InvestigationReport.model_json_schema())}\n\n"
        "Rules: `evidence` must contain only observed facts drawn from the data "
        "below (log lines, event IDs, raw findings) -- never invent evidence not "
        "present here. `observations` is your interpretation, kept separate from "
        "`evidence`. `affected_devices` must be a list of device_id values actually "
        f"present in the evidence.\n\nEvidence:\n{json.dumps(evidence_payload, default=str)}"
    )


def investigate(
    client: LLMClient, toolkit: AgentToolkit, incident_id: str, device_id: str
) -> InvestigationReport:
    """Run the Investigation Agent for one incident.

    Raises `AgentStalledError` (see `app/agents/base.py`) if the LLM cannot
    produce a schema-valid `InvestigationReport` after one retry -- the
    incident is marked `INVESTIGATION_STALLED` before the exception
    propagates, per Section 11's failure-handling requirement.
    """
    prompt = _build_prompt(incident_id, device_id, toolkit)
    return run_agent_call(
        client=client,
        toolkit=toolkit,
        agent_name=_AGENT_NAME,
        incident_id=incident_id,
        prompt=prompt,
        output_schema=InvestigationReport,
        input_payload={"incident_id": incident_id, "device_id": device_id},
        stall_status=IncidentStatus.INVESTIGATION_STALLED,
    )
