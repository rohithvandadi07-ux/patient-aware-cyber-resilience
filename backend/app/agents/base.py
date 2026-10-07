"""Shared agent-call scaffolding: prompt -> validate -> trace -> stall-on-failure.

Every one of the five agents (Section 11) follows the same shape: build a
prompt from real tool-fetched evidence, call the LLM, validate the structured
output, write an agent trace either way, and -- on an `AgentFailure` after
retry -- mark the incident stalled rather than guessing (architecture spec:
"an agent that can't produce a valid structured output after retry marks the
incident `investigation_stalled` (or the equivalent per stage) and surfaces it
on the dashboard rather than guessing"). This module holds that shared shape
once, so each agent module only supplies its own prompt-building and its own
"equivalent per stage" stall status.
"""

from typing import TypeVar

from pydantic import BaseModel

from app.agents.llm_client import AgentFailure, LLMClient, generate_validated
from app.agents.tools import AgentToolkit
from app.schemas.enums import IncidentStatus

T = TypeVar("T", bound=BaseModel)


class AgentStalledError(Exception):
    """Raised by an agent's `run()` after it has recorded a failed trace and
    marked the incident at its stall status. Callers (the eventual Phase 4+
    orchestrator) catch this to stop the pipeline at this stage rather than
    passing `None` downstream."""

    def __init__(self, agent_name: str, incident_id: str, stall_status: IncidentStatus) -> None:
        self.agent_name = agent_name
        self.incident_id = incident_id
        self.stall_status = stall_status
        super().__init__(
            f"{agent_name} stalled on incident {incident_id!r}; marked {stall_status.value}"
        )


def run_agent_call(
    *,
    client: LLMClient,
    toolkit: AgentToolkit,
    agent_name: str,
    incident_id: str,
    prompt: str,
    output_schema: type[T],
    input_payload: dict,
    stall_status: IncidentStatus,
) -> T:
    """Run one agent's LLM call with validation, retry, and tracing.

    On success: records a success trace and returns the validated output.
    On failure (AgentFailure after retry): records a failure trace, updates
    the incident to `stall_status`, and raises `AgentStalledError` -- the
    caller (each agent's own `run()`) is expected to let this propagate, not
    swallow it, per the architecture spec's "does not silently proceed on bad
    agent output."
    """
    try:
        output = generate_validated(client, prompt, output_schema, agent_name=agent_name)
    except AgentFailure as failure:
        toolkit.trace_recorder.record_failure(
            incident_id=incident_id,
            agent_name=agent_name,
            input_payload=input_payload,
            error=str(failure),
        )
        toolkit.incident_repository.update_status(incident_id, stall_status)
        raise AgentStalledError(agent_name, incident_id, stall_status) from failure

    toolkit.trace_recorder.record_success(
        incident_id=incident_id,
        agent_name=agent_name,
        input_payload=input_payload,
        output_payload=output.model_dump(mode="json"),
    )
    return output
