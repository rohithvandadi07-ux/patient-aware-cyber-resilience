"""Stores for the L6/L7 response lifecycle's two API-visible states: a
`PolicyDecision` awaiting execution ("proposed"), and an `ExecutedResponse`
once the Response Orchestrator has actually run it. In-memory by default; a
real Postgres-backed implementation of each is available via
`Settings.repository_backend = "postgres"`.

Neither of these existed before Phase 9 because nothing before the API
layer needed to hold a `PolicyDecision` across a request boundary -- Phase
6's `PolicyEngine.evaluate`/`evaluate_action` and Phase 6/7's
`ResponseOrchestrator.execute` are both pure, stateless calls (schema in,
schema out). The `/responses/proposed` and `/responses/executed` API
routers (architecture spec Section 15) are the first callers that need a
decision to survive between "the Policy Engine decided this" and "a human
approved it, now execute" -- two separate HTTP requests, per Section 7 steps
9-11. `ProposedResponseRepository`/`ExecutedResponseRepository` (below) were
Phase 9's in-memory stand-ins; `PostgresProposedResponseRepository`/
`PostgresExecutedResponseRepository`, added later, are the real
Postgres-backed ones -- same public methods, backed by the
`proposed_responses`/`executed_responses` tables (`app/models/orm.py`)
instead of a dict/list.
"""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import ExecutedResponseORM, ProposedResponseORM
from app.schemas.enums import ResponseActionCategory
from app.schemas.policy import AlternativeAction, PolicyDecision
from app.schemas.response import ExecutedResponse


class ProposedResponseNotFoundError(KeyError):
    """Raised when an incident_id has no pending `PolicyDecision`."""


class ProposedResponseRepository:
    """Holds at most one pending `PolicyDecision` per incident -- the most
    recent one the Policy Engine produced for that incident. A second
    `put()` for the same incident_id replaces the prior entry rather than
    accumulating a history, because only the latest decision is actionable;
    `/blockchain/audit` and `/agents` are where the historical trail lives,
    not here."""

    def __init__(self) -> None:
        self._decisions: dict[str, PolicyDecision] = {}

    def put(self, decision: PolicyDecision) -> PolicyDecision:
        self._decisions[decision.incident_id] = decision
        return decision

    def get(self, incident_id: str) -> PolicyDecision:
        try:
            return self._decisions[incident_id]
        except KeyError as exc:
            raise ProposedResponseNotFoundError(incident_id) from exc

    def list_all(self) -> list[PolicyDecision]:
        return list(self._decisions.values())

    def remove(self, incident_id: str) -> None:
        """No-op if nothing is pending for this incident -- called after a
        successful execution to clear the now-stale proposal; removing
        something already absent is not an error."""
        self._decisions.pop(incident_id, None)


class ExecutedResponseRepository:
    """Append-only log of every `ExecutedResponse` the Response Orchestrator
    has actually produced. Append-only (unlike `ProposedResponseRepository`,
    which replaces) because a reopened incident (Section 7 step 12) can be
    executed against more than once, and the dashboard's audit trail needs
    every execution, not just the latest."""

    def __init__(self) -> None:
        self._executed: list[ExecutedResponse] = []

    def record(self, executed: ExecutedResponse) -> ExecutedResponse:
        self._executed.append(executed)
        return executed

    def list_all(self) -> list[ExecutedResponse]:
        return list(self._executed)

    def list_for_incident(self, incident_id: str) -> list[ExecutedResponse]:
        return [e for e in self._executed if e.incident_id == incident_id]


def _decision_from_row(row: ProposedResponseORM) -> PolicyDecision:
    return PolicyDecision(
        incident_id=row.incident_id,
        chosen_action=ResponseActionCategory(row.chosen_action),
        requires_human_approval=row.requires_human_approval,
        policy_rule_id=row.policy_rule_id,
        rationale=row.rationale,
        alternatives=[AlternativeAction(**a) for a in (row.alternatives or [])],
    )


class PostgresProposedResponseRepository:
    """Real, Postgres-backed `ProposedResponseRepository` -- same public
    interface, backed by the `proposed_responses` table
    (`app/models/orm.py`) instead of a dict. One short-lived session per
    call (`session_scope`), matching `PostgresIncidentRepository`'s
    pattern. `put()` on an existing `incident_id` is a real `UPDATE`
    (matching the in-memory repository's replace-not-accumulate
    semantics), not an insert that would violate the primary key.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def put(self, decision: PolicyDecision) -> PolicyDecision:
        with session_scope(self._session_factory) as session:
            row = session.get(ProposedResponseORM, decision.incident_id)
            if row is None:
                row = ProposedResponseORM(incident_id=decision.incident_id)
                session.add(row)
            row.chosen_action = decision.chosen_action.value
            row.requires_human_approval = decision.requires_human_approval
            row.policy_rule_id = decision.policy_rule_id
            row.rationale = decision.rationale
            row.alternatives = [a.model_dump(mode="json") for a in decision.alternatives]
            session.flush()
        return decision

    def get(self, incident_id: str) -> PolicyDecision:
        with session_scope(self._session_factory) as session:
            row = session.get(ProposedResponseORM, incident_id)
            if row is None:
                raise ProposedResponseNotFoundError(incident_id)
            return _decision_from_row(row)

    def list_all(self) -> list[PolicyDecision]:
        with session_scope(self._session_factory) as session:
            rows = session.query(ProposedResponseORM).all()
            return [_decision_from_row(row) for row in rows]

    def remove(self, incident_id: str) -> None:
        with session_scope(self._session_factory) as session:
            row = session.get(ProposedResponseORM, incident_id)
            if row is not None:
                session.delete(row)


def _executed_from_row(row: ExecutedResponseORM) -> ExecutedResponse:
    return ExecutedResponse(
        incident_id=row.incident_id,
        action_taken=ResponseActionCategory(row.action_taken),
        executed_by=row.executed_by,
        timestamp=row.timestamp,
        chain_tx_id=row.chain_tx_id,
    )


class PostgresExecutedResponseRepository:
    """Real, Postgres-backed `ExecutedResponseRepository` -- same public
    interface, backed by the `executed_responses` table
    (`app/models/orm.py`) instead of a list. Append-only, like the
    in-memory repository: one short-lived session per call
    (`session_scope`), matching `PostgresIncidentRepository`'s pattern.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(self, executed: ExecutedResponse) -> ExecutedResponse:
        with session_scope(self._session_factory) as session:
            row = ExecutedResponseORM(
                incident_id=executed.incident_id,
                action_taken=executed.action_taken.value,
                executed_by=executed.executed_by,
                timestamp=executed.timestamp,
                chain_tx_id=executed.chain_tx_id,
            )
            session.add(row)
            session.flush()
        return executed

    def list_all(self) -> list[ExecutedResponse]:
        with session_scope(self._session_factory) as session:
            rows = session.query(ExecutedResponseORM).all()
            return [_executed_from_row(row) for row in rows]

    def list_for_incident(self, incident_id: str) -> list[ExecutedResponse]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(ExecutedResponseORM)
                .filter(ExecutedResponseORM.incident_id == incident_id)
                .all()
            )
            return [_executed_from_row(row) for row in rows]
