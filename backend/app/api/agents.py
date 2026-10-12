"""`/agents` — read-only view onto the agent-trace table (L4, architecture
spec Section 3's Risk 4 resolution and Section 8's storage strategy).

Architecture spec Section 16: "The Agent Activity panel reads directly from
the agent-trace table ... so it shows what each agent actually received and
produced for this incident, not a narrated summary ... an agent that hasn't
run for this incident shows as not-run, not blank." This router is that read
path over HTTP, over `AgentTraceRecorder` (Phase 4, `app/repositories/agent_traces.py`).

Deliberately no endpoint to *run* an agent here. `app/agents/README.md`'s own
"known gaps" section: "No orchestration layer sequences the five agents
automatically yet" and no real `LLMClient` backend is wired in anywhere
(`app/agents/llm_client.py`'s module docstring -- "that stays an open Phase
4+ decision ... building it now would be choosing a backend under feature
pressure rather than after the schemas are proven"). An HTTP endpoint that
"ran" an agent today could only do so against `MockLLMClient`'s pre-scripted
responses, which would make the endpoint non-functional for any real caller
-- building that now would be fabricating working functionality this project
does not actually have, not backend integration. The five agents stay
callable as plain Python functions (`investigate`, `assess_threat`, etc.)
for whichever later phase wires a real LLM backend and an orchestrator.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.dependencies import get_agent_trace_recorder
from app.repositories.agent_traces import AgentTraceRecorder

router = APIRouter(prefix="/agents", tags=["agents"])


class AgentTraceOut(BaseModel):
    """`AgentTrace` (a plain dataclass, not a Pydantic model -- see
    `app/repositories/agent_traces.py`) re-shaped as the API's response
    schema, field-for-field, with no added or dropped information."""

    incident_id: str
    agent_name: str
    input_payload: dict
    output_payload: dict | None
    succeeded: bool
    recorded_at: str
    error: str | None = None

    @classmethod
    def from_trace(cls, trace) -> "AgentTraceOut":
        return cls(
            incident_id=trace.incident_id,
            agent_name=trace.agent_name,
            input_payload=trace.input_payload,
            output_payload=trace.output_payload,
            succeeded=trace.succeeded,
            recorded_at=trace.recorded_at.isoformat(),
            error=trace.error,
        )


@router.get("", response_model=list[AgentTraceOut])
async def list_agent_traces(
    incident_id: str | None = None,
    agent_name: str | None = None,
    recorder: AgentTraceRecorder = Depends(get_agent_trace_recorder),
) -> list[AgentTraceOut]:
    """Every agent call trace recorded so far, optionally filtered by
    incident and/or agent name. Empty, never fabricated, when nothing has
    run for the given filter -- the dashboard's "not-run, not blank"
    requirement (Section 16) starts here."""
    traces = recorder.all_traces()
    if incident_id is not None:
        traces = [t for t in traces if t.incident_id == incident_id]
    if agent_name is not None:
        traces = [t for t in traces if t.agent_name == agent_name]
    return [AgentTraceOut.from_trace(t) for t in traces]


@router.get("/{incident_id}", response_model=list[AgentTraceOut])
async def list_agent_traces_for_incident(
    incident_id: str, recorder: AgentTraceRecorder = Depends(get_agent_trace_recorder)
) -> list[AgentTraceOut]:
    return [AgentTraceOut.from_trace(t) for t in recorder.list_for_incident(incident_id)]
