"""Healthcare Context Agent (L4, third of the five).

Architecture spec Section 11: input `incident_id`, `affected_devices`; tool
`get_device_state`; output `ClinicalContext {device_criticality,
patient_dependency, clinical_impact_level, safety_constraints}`. Section 9:
this agent reads through the same `get_device_state` the simulator and API
layer use -- "one source of truth," never a duplicated/invented copy of
clinical attributes.

Note on scope: `ClinicalContext` (Section 11's table) carries single
`device_criticality`/`patient_dependency` fields, which is well-defined for
the common case of one primary affected device even though `affected_devices`
is a list. When `affected_devices` has more than one device, this agent
reports on the single most clinically significant one (highest criticality,
ties broken by patient_dependency) and lists every device actually queried in
the prompt data -- it does not silently pick the first device in the list or
average across devices, since neither is a real measurement.
"""

import json

from app.agents.base import run_agent_call
from app.agents.llm_client import LLMClient
from app.agents.tools import AgentToolkit
from app.schemas.agents import ClinicalContext
from app.schemas.device import DeviceState
from app.schemas.enums import DeviceCriticality, IncidentStatus

_AGENT_NAME = "healthcare_context"

_CRITICALITY_ORDER = {DeviceCriticality.LOW: 0, DeviceCriticality.MEDIUM: 1, DeviceCriticality.HIGH: 2}


def _most_clinically_significant(devices: list[DeviceState]) -> DeviceState:
    return max(
        devices,
        key=lambda d: (_CRITICALITY_ORDER[d.criticality], d.patient_dependency),
    )


def _build_prompt(incident_id: str, affected_devices: list[DeviceState]) -> str:
    primary = _most_clinically_significant(affected_devices)
    payload = {
        "incident_id": incident_id,
        "primary_device": primary.model_dump(mode="json"),
        "all_affected_devices": [d.model_dump(mode="json") for d in affected_devices],
    }
    return (
        "You are the Healthcare Context Agent for a healthcare IoMT cyber-resilience "
        "system. Given the real device state(s) below for this incident, produce a "
        f"JSON object matching this schema: {json.dumps(ClinicalContext.model_json_schema())}\n\n"
        "Rules: `device_criticality` and `patient_dependency` must exactly match "
        "`primary_device`'s own fields below -- never invent or infer a different "
        "value. `clinical_impact_level` is your estimate of impact if this device "
        "were disrupted, grounded in its criticality and whether a patient depends "
        "on it. `safety_constraints` must be concrete, device-specific constraints "
        "(e.g. 'ventilator must not be powered off while patient_dependency is "
        "true'), not generic security advice.\n\n"
        f"Data:\n{json.dumps(payload, default=str)}"
    )


def assess_clinical_context(
    client: LLMClient, toolkit: AgentToolkit, incident_id: str, affected_devices: list[str]
) -> ClinicalContext:
    """Run the Healthcare Context Agent for one incident.

    Raises `AgentStalledError` and marks the incident `CONTEXT_STALLED` if the
    LLM cannot produce a valid `ClinicalContext` after one retry.
    """
    if not affected_devices:
        raise ValueError("affected_devices must be non-empty -- nothing to assess clinical context for")

    device_states = [toolkit.get_device_state(device_id) for device_id in affected_devices]
    prompt = _build_prompt(incident_id, device_states)
    return run_agent_call(
        client=client,
        toolkit=toolkit,
        agent_name=_AGENT_NAME,
        incident_id=incident_id,
        prompt=prompt,
        output_schema=ClinicalContext,
        input_payload={"incident_id": incident_id, "affected_devices": affected_devices},
        stall_status=IncidentStatus.CONTEXT_STALLED,
    )
