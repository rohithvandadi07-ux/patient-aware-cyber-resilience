"""Recovery Verification Agent (L4, fifth and last of the five).

Architecture spec Section 11: input `incident_id`, executed `response_id`;
tools `get_device_state`, `get_network_events`; output `RecoveryResult
{containment_verified, residual_threats, recovery_succeeded,
reinvestigation_required}`. Section 7, step 12: "The Recovery Verification
Agent re-checks device/network state after a cooldown. Success closes the
incident; failure re-opens it at step 4 with the new evidence appended."

**response_id note:** there is no Response Orchestrator or executed-response
record store yet (Section 14/L7, Phase 6/7 work) -- `response_id` here is
treated as an opaque reference string the caller already has (e.g. from
whatever later phase executes a response), not something this agent looks up
or validates against a store that doesn't exist. It is passed through into
the prompt and the trace for correlation, nothing more.
"""

import json

from app.agents.base import run_agent_call
from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.schemas.agents import RecoveryResult
from app.schemas.enums import IncidentStatus

_AGENT_NAME = "recovery_verification"


def _build_prompt(incident_id: str, response_id: str, device_id: str, toolkit: AgentToolkit) -> str:
    device_state = toolkit.get_device_state(device_id)
    network_events = toolkit.get_network_events(device_id)

    payload = {
        "incident_id": incident_id,
        "response_id": response_id,
        "current_device_state": device_state.model_dump(mode="json"),
        "network_events_since_response": [e.model_dump(mode="json") for e in network_events],
    }
    return (
        "You are the Recovery Verification Agent for a healthcare IoMT "
        "cyber-resilience system. A response action was executed for this incident "
        "(response_id below); given the device's current real state and its recent "
        "network events, produce a JSON object matching this schema: "
        f"{json.dumps(RecoveryResult.model_json_schema())}\n\n"
        "Rules: `containment_verified` and `recovery_succeeded` must be grounded in "
        "the device state and events below, not assumed from the response having "
        "been executed. `residual_threats` lists any evidence of continuing "
        "compromise. `reinvestigation_required` should be true whenever containment "
        "is not clearly verified -- per this system's design, failure re-opens the "
        "incident for a fresh investigation rather than being silently accepted.\n\n"
        f"Data:\n{json.dumps(payload, default=str)}"
    )


def verify_recovery(
    client: LLMClient, toolkit: AgentToolkit, incident_id: str, response_id: str, device_id: str
) -> RecoveryResult:
    """Run the Recovery Verification Agent.

    Raises `AgentStalledError` and marks the incident
    `RECOVERY_VERIFICATION_STALLED` if the LLM cannot produce a valid
    `RecoveryResult` after one retry.

    This function does not itself close or re-open the incident based on the
    result's `recovery_succeeded`/`reinvestigation_required` fields -- Section
    7 step 12's "success closes the incident; failure re-opens it at step 4"
    is the Recovery Orchestrator's job (L8, `app/recovery/engine.py`,
    `RecoveryOrchestrator.process_result`, built in Phase 7), the same
    separation Phase 6 drew between the Response Planning Agent (proposes)
    and the Policy Engine/Response Orchestrator (decide and act). Call
    `verify_recovery` for the `RecoveryResult`, then pass that result to
    `RecoveryOrchestrator.process_result` to actually transition the
    incident -- this function still does not do that itself.
    """
    prompt = _build_prompt(incident_id, response_id, device_id, toolkit)
    return run_agent_call(
        client=client,
        toolkit=toolkit,
        agent_name=_AGENT_NAME,
        incident_id=incident_id,
        prompt=prompt,
        output_schema=RecoveryResult,
        input_payload={"incident_id": incident_id, "response_id": response_id, "device_id": device_id},
        stall_status=IncidentStatus.RECOVERY_VERIFICATION_STALLED,
    )
