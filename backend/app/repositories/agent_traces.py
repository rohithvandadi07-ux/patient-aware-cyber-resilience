"""In-memory agent-trace recorder.

Architecture spec Section 3, Risk 4 resolution: "Every agent call writes its
structured input and output to the incident's agent-trace table before
returning. This makes each agent's logic independently testable [...] and
gives the SOC dashboard's 'Agent Activity' section real data rather than
invented narration." Section 8 names this as its own PostgreSQL table per
agent type, foreign-keyed to incident -- that's Phase 9's persistence layer.

For Phase 4, this module gives every agent a real place to write its trace to
and real data for tests to assert against (did the agent's input/output
actually get recorded?), without depending on a database that doesn't exist
yet. Phase 9 replaces `AgentTraceRecorder`'s storage with Postgres without
changing `record()`'s signature or the `AgentTrace` shape callers see.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class AgentTrace:
    """One agent call's full input/output record."""

    incident_id: str
    agent_name: str
    input_payload: dict[str, Any]
    output_payload: dict[str, Any] | None
    succeeded: bool
    recorded_at: datetime
    error: str | None = None


class AgentTraceRecorder:
    def __init__(self) -> None:
        self._traces: list[AgentTrace] = []

    def record_success(
        self, incident_id: str, agent_name: str, input_payload: dict, output_payload: dict
    ) -> AgentTrace:
        trace = AgentTrace(
            incident_id=incident_id,
            agent_name=agent_name,
            input_payload=input_payload,
            output_payload=output_payload,
            succeeded=True,
            recorded_at=datetime.now(UTC),
        )
        self._traces.append(trace)
        return trace

    def record_failure(
        self, incident_id: str, agent_name: str, input_payload: dict, error: str
    ) -> AgentTrace:
        trace = AgentTrace(
            incident_id=incident_id,
            agent_name=agent_name,
            input_payload=input_payload,
            output_payload=None,
            succeeded=False,
            recorded_at=datetime.now(UTC),
            error=error,
        )
        self._traces.append(trace)
        return trace

    def list_for_incident(self, incident_id: str) -> list[AgentTrace]:
        return [t for t in self._traces if t.incident_id == incident_id]

    def list_for_agent(self, agent_name: str) -> list[AgentTrace]:
        return [t for t in self._traces if t.agent_name == agent_name]

    def all_traces(self) -> list[AgentTrace]:
        return list(self._traces)
