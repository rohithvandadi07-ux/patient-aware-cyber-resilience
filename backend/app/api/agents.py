"""`/agents` — read-only view onto the agent-trace table (L4, architecture
spec Section 3's Risk 4 resolution and Section 8's storage strategy).

Architecture spec Section 16: "The Agent Activity panel reads directly from
the agent-trace table ... so it shows what each agent actually received and
produced for this incident, not a narrated summary ... an agent that hasn't
run for this incident shows as not-run, not blank." This router is that read
path over HTTP, over `AgentTraceRecorder` (Phase 4, `app/repositories/agent_traces.py`).

**Post-Phase-15 update:** a real orchestration layer and a real LLM backend
now both exist (`app/orchestration/orchestrator.py`'s `IncidentOrchestrator`,
`app/agents/llm_client.py`'s `GeminiLLMClient`) -- but the endpoint that
actually *runs* the five agents lives on `/incidents/{id}/investigate`
(`app/api/incidents.py`), not here, because running an agent only makes
sense in the context of one incident's lifecycle, which that router already
owns. This router stays exactly what its own docstring above says: a
read-only view onto whatever traces running that pipeline produced. The
traces it serves are real either way -- scripted via `MockLLMClient` when
`Settings.llm_backend` is at its default ("mock"), or genuinely
model-produced when `llm_backend="gemini"` with a real key is configured;
this endpoint cannot tell the difference and does not claim to.
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
