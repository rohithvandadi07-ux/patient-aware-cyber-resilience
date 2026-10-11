"""RecoveryOrchestrator -- L8, the deterministic service that closes the loop
Section 7 step 12 describes: "The Recovery Verification Agent re-checks
device/network state after a cooldown. Success closes the incident; failure
re-opens it at step 4 with the new evidence appended." Section 4's component
diagram calls this the dashed loop: "if L8 (Recovery Verification) finds
containment failed, the incident re-opens at L4 rather than silently
closing."

Same relationship to the L4 Recovery Verification Agent
(`app/agents/recovery_verification.py`) as the Policy Engine (L6) has to the
Response Planning Agent, and the Response Orchestrator (L7) has to the
Policy Engine: the agent produces a structured, LLM-derived finding and
deliberately does *not* act on it (see that module's own docstring); this
class is the separate, non-agentic, deterministic service that turns the
finding into the actual incident-lifecycle transition and persists it as
queryable evidence.

**Routing rule:** `reinvestigation_required` is the field the Recovery
Verification Agent's own prompt (and docstring) singles out as the
authoritative "should this reopen" signal -- "`reinvestigation_required`
should be true whenever containment is not clearly verified ... failure
re-opens the incident ... rather than being silently accepted." So this
orchestrator routes on `reinvestigation_required` first, before
`recovery_succeeded`:

  1. `reinvestigation_required == True` -> `IncidentStatus.REOPENED`,
     regardless of `recovery_succeeded` (the conservative choice: even a
     `RecoveryResult` that claims both "recovery succeeded" and
     "reinvestigation required" reopens -- reinvestigation is the
     safety-relevant flag).
  2. `reinvestigation_required == False and recovery_succeeded == True` ->
     `IncidentStatus.RESOLVED`.
  3. `reinvestigation_required == False and recovery_succeeded == False` ->
     raises `InconsistentRecoveryResultError`. This combination contradicts
     the agent's own stated contract (failure should set
     `reinvestigation_required=True`), so this orchestrator refuses to guess
     which field to trust rather than silently resolving or reopening an
     incident on a self-contradictory finding.

Every `RecoveryResult` is recorded into `RecoveryResultRepository` before
routing is attempted (including in the error case) -- the evidence itself is
never lost even when the routing decision is refused.
"""

from app.repositories.incidents import IncidentRepository
from app.repositories.recovery_results import RecoveryResultRepository
from app.schemas.agents import RecoveryResult
from app.schemas.enums import IncidentStatus
from app.schemas.incident import Incident


class InconsistentRecoveryResultError(ValueError):
    """Raised when a `RecoveryResult` reports `recovery_succeeded=False` and
    `reinvestigation_required=False` at once -- a combination the Recovery
    Verification Agent's own contract says should not happen (failure should
    always set `reinvestigation_required=True`). The result is still
    recorded as evidence; only the incident-status transition is refused."""


class RecoveryOrchestrator:
    """L8: the only service that transitions an incident to `RESOLVED` or
    `REOPENED` on the strength of a `RecoveryResult`."""

    def __init__(
        self,
        incident_repository: IncidentRepository,
        recovery_result_repository: RecoveryResultRepository,
    ) -> None:
        self._incident_repository = incident_repository
        self._recovery_result_repository = recovery_result_repository

    def process_result(self, result: RecoveryResult) -> Incident:
        """Record `result` as evidence, then transition the incident per the
        routing rule in this module's docstring.

        Raises `IncidentNotFoundError` (propagated from `IncidentRepository`)
        if `result.incident_id` is unknown -- checked *before* recording, so
        no evidence is filed against a nonexistent incident. Raises
        `InconsistentRecoveryResultError` for the self-contradictory case
        above, after recording.
        """
        self._incident_repository.get(result.incident_id)
        self._recovery_result_repository.record(result)

        if result.reinvestigation_required:
            return self._incident_repository.update_status(result.incident_id, IncidentStatus.REOPENED)
        if result.recovery_succeeded:
            return self._incident_repository.update_status(result.incident_id, IncidentStatus.RESOLVED)

        raise InconsistentRecoveryResultError(
            f"RecoveryResult for incident {result.incident_id!r} reports "
            "recovery_succeeded=False and reinvestigation_required=False -- this contradicts the "
            "Recovery Verification Agent's own contract (reinvestigation_required should be true "
            "whenever containment is not clearly verified). Refusing to guess whether to resolve "
            "or reopen; the result has been recorded as evidence regardless."
        )
