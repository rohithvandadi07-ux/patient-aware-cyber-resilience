"""In-memory stores for the L6/L7 response lifecycle's two API-visible
states: a `PolicyDecision` awaiting execution ("proposed"), and an
`ExecutedResponse` once the Response Orchestrator has actually run it.

Neither of these existed before Phase 9 because nothing before the API
layer needed to hold a `PolicyDecision` across a request boundary -- Phase
6's `PolicyEngine.evaluate`/`evaluate_action` and Phase 6/7's
`ResponseOrchestrator.execute` are both pure, stateless calls (schema in,
schema out). The `/responses/proposed` and `/responses/executed` API
routers (architecture spec Section 15) are the first callers that need a
decision to survive between "the Policy Engine decided this" and "a human
approved it, now execute" -- two separate HTTP requests, per Section 7 steps
9-11. These two repositories are that survival, in the same in-memory,
one-repository-per-aggregate pattern as every other repository in this
codebase (`app/repositories/*.py`, `app/blockchain/outbox.py`) -- a real
Postgres-backed swap later is a constructor change, not an API rewrite.
"""

from __future__ import annotations

from app.schemas.policy import PolicyDecision
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
