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

import logging
from collections.abc import Callable
from typing import TypeVar

from pydantic import BaseModel

from app.agents.llm_client import AgentFailure, LLMClient, generate_validated
from app.agents.tools import AgentToolkit
from app.schemas.enums import IncidentStatus

logger = logging.getLogger(__name__)

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
    ground: Callable[[T], tuple[T, list[str]]] | None = None,
) -> T:
    """Run one agent's LLM call with validation, retry, and tracing.

    On success: records a success trace and returns the validated output.
    On failure (AgentFailure after retry): records a failure trace, updates
    the incident to `stall_status`, and raises `AgentStalledError` -- the
    caller (each agent's own `run()`) is expected to let this propagate, not
    swallow it, per the architecture spec's "does not silently proceed on bad
    agent output."

    Two deterministic guards (`app.agents.grounding`) sit around the LLM call:
    an output naming a different incident is a validation failure, and an
    optional `ground` callback may correct a claim the system can check against
    its own records. When `ground` changes anything, the corrections are logged
    at WARNING and the trace carries both the corrected output and the
    corrections, so a manipulated or mistaken agent is visible, not silent.
    """
    try:
        output = generate_validated(
            client, prompt, output_schema, agent_name=agent_name, expected_incident_id=incident_id
        )
    except AgentFailure as failure:
        toolkit.trace_recorder.record_failure(
            incident_id=incident_id,
            agent_name=agent_name,
            input_payload=input_payload,
            error=str(failure),
        )
        toolkit.incident_repository.update_status(incident_id, stall_status)
        raise AgentStalledError(agent_name, incident_id, stall_status) from failure

    output_payload = output.model_dump(mode="json")
    if ground is not None:
        grounded, corrections = ground(output)
        if corrections:
            logger.warning(
                "%s output corrected against ground truth for incident %s: %s",
                agent_name,
                incident_id,
                "; ".join(corrections),
            )
            output_payload = {
                **grounded.model_dump(mode="json"),
                "grounding_corrections": corrections,
                "agent_output_before_grounding": output_payload,
            }
            output = grounded

    toolkit.trace_recorder.record_success(
        incident_id=incident_id,
        agent_name=agent_name,
        input_payload=input_payload,
        output_payload=output_payload,
    )
    return output
