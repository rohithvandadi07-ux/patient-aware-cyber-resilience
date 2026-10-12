"""Agent-trace recorder -- in-memory by default, a real Postgres-backed
implementation available via `Settings.repository_backend = "postgres"`.

Architecture spec Section 3, Risk 4 resolution: "Every agent call writes its
structured input and output to the incident's agent-trace table before
returning. This makes each agent's logic independently testable [...] and
gives the SOC dashboard's 'Agent Activity' section real data rather than
invented narration." Section 8 names this as its own PostgreSQL table,
foreign-keyed to incident. `AgentTraceRecorder` (below) was Phase 4's
in-memory stand-in; `PostgresAgentTraceRecorder`, added later, is the real
Postgres-backed one -- same public methods and the same `AgentTrace` shape
callers see, backed by the `agent_traces` table instead of a list.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import AgentTraceORM


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


def _trace_from_row(row: AgentTraceORM) -> AgentTrace:
    return AgentTrace(
        incident_id=row.incident_id,
        agent_name=row.agent_name,
        input_payload=row.input_payload,
        output_payload=row.output_payload,
        succeeded=row.succeeded,
        recorded_at=row.recorded_at,
        error=row.error,
    )


class PostgresAgentTraceRecorder:
    """Real, Postgres-backed `AgentTraceRecorder` -- same public interface
    and the same `AgentTrace` shape callers see, backed by the
    `agent_traces` table (`app/models/orm.py`) instead of a list. One
    short-lived session per call (`session_scope`), matching
    `PostgresIncidentRepository`'s pattern.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_success(
        self, incident_id: str, agent_name: str, input_payload: dict, output_payload: dict
    ) -> AgentTrace:
        with session_scope(self._session_factory) as session:
            row = AgentTraceORM(
                incident_id=incident_id,
                agent_name=agent_name,
                input_payload=input_payload,
                output_payload=output_payload,
                succeeded=True,
                recorded_at=datetime.now(UTC),
            )
            session.add(row)
            session.flush()
            return _trace_from_row(row)

    def record_failure(
        self, incident_id: str, agent_name: str, input_payload: dict, error: str
    ) -> AgentTrace:
        with session_scope(self._session_factory) as session:
            row = AgentTraceORM(
                incident_id=incident_id,
                agent_name=agent_name,
                input_payload=input_payload,
                output_payload=None,
                succeeded=False,
                recorded_at=datetime.now(UTC),
                error=error,
            )
            session.add(row)
            session.flush()
            return _trace_from_row(row)

    def list_for_incident(self, incident_id: str) -> list[AgentTrace]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(AgentTraceORM)
                .filter(AgentTraceORM.incident_id == incident_id)
                .all()
            )
            return [_trace_from_row(row) for row in rows]

    def list_for_agent(self, agent_name: str) -> list[AgentTrace]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(AgentTraceORM)
                .filter(AgentTraceORM.agent_name == agent_name)
                .all()
            )
            return [_trace_from_row(row) for row in rows]

    def all_traces(self) -> list[AgentTrace]:
        with session_scope(self._session_factory) as session:
            rows = session.query(AgentTraceORM).all()
            return [_trace_from_row(row) for row in rows]
