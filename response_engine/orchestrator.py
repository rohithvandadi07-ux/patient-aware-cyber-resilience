"""Response orchestration and the response state machine.

Owns the transition from a *recommended* action to an *executed* one, and is
the only component permitted to actuate. The sequence is fixed:

    PROPOSED -> POLICY_CHECK -> {DENIED | APPROVAL_REQUIRED | AUTO_ALLOWED}
             -> APPROVED -> EXECUTING -> {EXECUTED | FAILED}
             -> RECOVERY_CHECK -> {RECOVERED | RESIDUAL_RISK}
             -> {RESOLVED | REINVESTIGATION}

Two properties are enforced structurally rather than by convention:

* **Policy check cannot be skipped.** ``execute`` refuses a response that
  has not passed through ``evaluate``, and refuses one whose verdict was
  DENIED or whose approval is not granted. An orchestration bug therefore
  fails loudly instead of quietly actuating an unapproved action.
* **Only this module calls the simulator's actuation method.** Agents hold
  no actuation tool (see ``agents/tools/registry.py``), so there is exactly
  one code path from decision to effect, and it passes through the policy
  engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from backend.app.domain.enums import (
    ApprovalStatus,
    PolicyDecision,
    ResponseState,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    ApprovalRecord,
    ClinicalRiskResult,
    CyberRiskResult,
    DeviceProfile,
    DeviceState,
    PolicyEvaluation,
    ResponseCandidate,
    ResponseImpactResult,
    ResponseRecord,
)
from response_engine.policy import PolicyContext, PolicyEngine

#: Legal transitions of the response state machine.
RESPONSE_TRANSITIONS: dict[ResponseState, frozenset[ResponseState]] = {
    ResponseState.PROPOSED: frozenset({ResponseState.POLICY_CHECK}),
    ResponseState.POLICY_CHECK: frozenset(
        {
            ResponseState.DENIED,
            ResponseState.APPROVAL_REQUIRED,
            ResponseState.AUTO_ALLOWED,
        }
    ),
    ResponseState.APPROVAL_REQUIRED: frozenset({ResponseState.APPROVED, ResponseState.REJECTED}),
    ResponseState.AUTO_ALLOWED: frozenset({ResponseState.EXECUTING}),
    ResponseState.APPROVED: frozenset({ResponseState.EXECUTING}),
    ResponseState.EXECUTING: frozenset({ResponseState.EXECUTED, ResponseState.FAILED}),
    ResponseState.EXECUTED: frozenset({ResponseState.RECOVERY_CHECK}),
    ResponseState.RECOVERY_CHECK: frozenset(
        {ResponseState.RECOVERED, ResponseState.RESIDUAL_RISK, ResponseState.FAILED}
    ),
    ResponseState.RECOVERED: frozenset({ResponseState.RESOLVED}),
    ResponseState.RESIDUAL_RISK: frozenset({ResponseState.REINVESTIGATION}),
    ResponseState.FAILED: frozenset({ResponseState.REINVESTIGATION}),
    # Terminal
    ResponseState.DENIED: frozenset(),
    ResponseState.REJECTED: frozenset(),
    ResponseState.RESOLVED: frozenset(),
    ResponseState.REINVESTIGATION: frozenset(),
}

#: States from which no execution may follow.
BLOCKED_STATES: frozenset[ResponseState] = frozenset({ResponseState.DENIED, ResponseState.REJECTED})


class IllegalResponseTransition(ValueError):
    """Raised when a response is moved along an undeclared edge."""


class UnauthorisedExecution(RuntimeError):
    """Raised when execution is attempted without a permitting verdict.

    This is a programming error in the orchestration, not a runtime
    condition to handle: it means a code path reached actuation without the
    policy engine having allowed it.
    """


def assert_response_transition(current: ResponseState, target: ResponseState) -> None:
    allowed = RESPONSE_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise IllegalResponseTransition(
            f"{current.value} -> {target.value} is not a legal response "
            f"transition. Legal from {current.value}: "
            f"{sorted(s.value for s in allowed) or 'none (terminal)'}."
        )


#: Signature of the actuator the orchestrator drives. Returns a structured
#: result describing what actually changed.
Actuator = Callable[[str, str | None, str | None], dict[str, Any]]


@dataclass
class ResponseOrchestrator:
    """Drives one response through the state machine."""

    policy: PolicyEngine
    ids: IdFactory
    clock: Clock
    actuator: Actuator | None = None
    #: Approvals granted out of band, keyed by response_id. In the backend
    #: this is the approval API; in experiments it is a scripted policy.
    approval_resolver: Callable[[ApprovalRecord], ApprovalStatus] | None = None
    _autonomous_taken: dict[str, int] = field(default_factory=dict, init=False)

    # -- 1. propose --------------------------------------------------------
    def propose(
        self,
        incident_id: str,
        candidate: ResponseCandidate,
        attempt_number: int = 1,
    ) -> ResponseRecord:
        now = self.clock.now()
        return ResponseRecord(
            response_id=self.ids.response(),
            incident_id=incident_id,
            candidate=candidate,
            state=ResponseState.PROPOSED,
            proposed_at=now,
            attempt_number=attempt_number,
            transitions=[
                {
                    "at": now.isoformat(),
                    "from": None,
                    "to": ResponseState.PROPOSED.value,
                    "by": candidate.proposed_by,
                }
            ],
        )

    # -- 2. policy check ---------------------------------------------------
    def evaluate(
        self,
        response: ResponseRecord,
        impact: ResponseImpactResult,
        cyber_risk: CyberRiskResult,
        clinical_risk: ClinicalRiskResult,
        device: DeviceProfile | None = None,
        state: DeviceState | None = None,
        already_attempted: bool = False,
    ) -> ResponseRecord:
        """Run the deterministic policy engine. Cannot be skipped."""
        response = self._transition(response, ResponseState.POLICY_CHECK, "orchestrator")

        ctx = PolicyContext(
            action=response.candidate.action_type,
            impact=impact,
            cyber_risk=cyber_risk,
            clinical_risk=clinical_risk,
            device=device,
            state=state,
            already_attempted=already_attempted,
            autonomous_actions_taken=self._autonomous_taken.get(response.incident_id, 0),
        )
        verdict = self.policy.evaluate(ctx)

        target = {
            PolicyDecision.DENIED: ResponseState.DENIED,
            PolicyDecision.APPROVAL_REQUIRED: ResponseState.APPROVAL_REQUIRED,
            PolicyDecision.AUTO_ALLOWED: ResponseState.AUTO_ALLOWED,
        }[verdict.decision]

        response = response.model_copy(update={"policy": verdict, "impact": impact})
        response = self._transition(response, target, f"policy:{verdict.matched_rule}")

        if target is ResponseState.APPROVAL_REQUIRED:
            response = self._open_approval(response, verdict)
        return response

    def _open_approval(self, response: ResponseRecord, verdict: PolicyEvaluation) -> ResponseRecord:
        now = self.clock.now()
        approval = ApprovalRecord(
            approval_id=self.ids.approval(),
            incident_id=response.incident_id,
            response_id=response.response_id,
            status=ApprovalStatus.PENDING,
            requested_at=now,
            required_role=verdict.required_role or "clinical_approver",
            justification=" ".join(verdict.reasons)[:2000],
            expires_at=now + timedelta(seconds=self.policy.approval_timeout_seconds),
        )
        return response.model_copy(update={"approval": approval})

    # -- 3. approval -------------------------------------------------------
    def resolve_approval(
        self,
        response: ResponseRecord,
        status: ApprovalStatus,
        approver: str,
        justification: str = "",
    ) -> ResponseRecord:
        """Record a human decision on a pending approval."""
        if response.approval is None:
            raise UnauthorisedExecution(
                f"response {response.response_id} has no pending approval to resolve"
            )
        if response.state is not ResponseState.APPROVAL_REQUIRED:
            raise IllegalResponseTransition(
                f"approval can only be resolved from APPROVAL_REQUIRED, not {response.state.value}"
            )
        now = self.clock.now()
        approval = response.approval.model_copy(
            update={
                "status": status,
                "decided_at": now,
                "approver": approver,
                "justification": justification or response.approval.justification,
            }
        )
        response = response.model_copy(update={"approval": approval})
        target = (
            ResponseState.APPROVED if status is ApprovalStatus.APPROVED else ResponseState.REJECTED
        )
        return self._transition(response, target, f"human:{approver}")

    def expire_approval(self, response: ResponseRecord) -> ResponseRecord:
        """Expire an unanswered approval.

        An unanswered request must never become consent, so an expiry is a
        rejection rather than a silent allow.
        """
        if response.approval is None:
            return response
        now = self.clock.now()
        approval = response.approval.model_copy(
            update={"status": ApprovalStatus.EXPIRED, "decided_at": now}
        )
        response = response.model_copy(update={"approval": approval})
        if self.policy.deny_on_timeout:
            return self._transition(response, ResponseState.REJECTED, "approval_timeout")
        return response  # pragma: no cover - only if a profile opts out

    # -- 4. execution ------------------------------------------------------
    def execute(self, response: ResponseRecord) -> ResponseRecord:
        """Actuate the response. Refuses anything not explicitly permitted."""
        self._assert_executable(response)

        response = self._transition(response, ResponseState.EXECUTING, "orchestrator")
        now = self.clock.now()
        action = response.candidate.action_type

        if self.actuator is None:
            raise UnauthorisedExecution(
                "no actuator is configured; the orchestrator cannot execute"
            )

        try:
            result = self.actuator(
                action.value,
                response.candidate.target_device_id,
                response.candidate.target_segment,
            )
            succeeded = bool(result.get("succeeded", False))
            detail = (
                f"affected {result.get('affected_devices', [])}"
                if succeeded
                else f"actuator reported failure: {result}"
            )
            side_effects = list(result.get("side_effects", []))
        except Exception as exc:
            succeeded = False
            detail = f"actuator raised {type(exc).__name__}: {exc}"
            side_effects = []

        response = response.model_copy(
            update={
                "executed_at": now,
                "execution_succeeded": succeeded,
                "execution_detail": detail,
                "side_effects": side_effects,
            }
        )
        response = self._transition(
            response,
            ResponseState.EXECUTED if succeeded else ResponseState.FAILED,
            "actuator",
        )
        if (
            succeeded
            and response.policy is not None
            and response.policy.decision is PolicyDecision.AUTO_ALLOWED
        ):
            self._autonomous_taken[response.incident_id] = (
                self._autonomous_taken.get(response.incident_id, 0) + 1
            )
        return response

    def _assert_executable(self, response: ResponseRecord) -> None:
        """The gate that makes policy unskippable."""
        if response.policy is None:
            raise UnauthorisedExecution(
                f"response {response.response_id} has not been evaluated by the "
                "policy engine. Execution without a policy verdict is "
                "forbidden; call evaluate() first."
            )
        if response.state in BLOCKED_STATES:
            raise UnauthorisedExecution(
                f"response {response.response_id} is {response.state.value} and "
                "must not be executed"
            )
        if response.policy.decision is PolicyDecision.DENIED:
            raise UnauthorisedExecution(
                f"policy DENIED {response.candidate.action_type.value} "
                f"(rule {response.policy.matched_rule}); execution refused"
            )
        if response.policy.decision is PolicyDecision.APPROVAL_REQUIRED:
            approval = response.approval
            if approval is None or approval.status is not ApprovalStatus.APPROVED:
                status = approval.status.value if approval else "missing"
                raise UnauthorisedExecution(
                    f"policy requires human approval for "
                    f"{response.candidate.action_type.value} but approval is "
                    f"{status}; execution refused"
                )
        if response.state not in {
            ResponseState.AUTO_ALLOWED,
            ResponseState.APPROVED,
        }:
            raise UnauthorisedExecution(
                f"response is {response.state.value}; only AUTO_ALLOWED or "
                "APPROVED responses may execute"
            )

    # -- 5. recovery outcome ----------------------------------------------
    def record_recovery_outcome(
        self, response: ResponseRecord, recovered: bool, residual_risk: float
    ) -> ResponseRecord:
        response = self._transition(response, ResponseState.RECOVERY_CHECK, "recovery_engine")
        target = ResponseState.RECOVERED if recovered else ResponseState.RESIDUAL_RISK
        response = self._transition(response, target, "recovery_engine")
        final = ResponseState.RESOLVED if recovered else ResponseState.REINVESTIGATION
        return self._transition(response, final, "recovery_engine")

    def mark_for_reinvestigation(self, response: ResponseRecord) -> ResponseRecord:
        return self._transition(response, ResponseState.REINVESTIGATION, "recovery_engine")

    # -- transitions -------------------------------------------------------
    def _transition(
        self, response: ResponseRecord, target: ResponseState, actor: str
    ) -> ResponseRecord:
        assert_response_transition(response.state, target)
        now = self.clock.now()
        return response.model_copy(
            update={
                "state": target,
                "transitions": [
                    *response.transitions,
                    {
                        "at": now.isoformat(),
                        "from": response.state.value,
                        "to": target.value,
                        "by": actor,
                    },
                ],
            }
        )

    # -- introspection -----------------------------------------------------
    def autonomous_actions_taken(self, incident_id: str) -> int:
        return self._autonomous_taken.get(incident_id, 0)

    def reset_incident(self, incident_id: str) -> None:
        self._autonomous_taken.pop(incident_id, None)


def validate_response_machine() -> None:
    """Structural invariants, asserted by the test suite."""
    for state in ResponseState:
        if state not in RESPONSE_TRANSITIONS:
            raise AssertionError(f"state {state.value} has no transition entry")

    # Execution must be reachable only from an explicitly permitting state.
    into_executing = {s for s, t in RESPONSE_TRANSITIONS.items() if ResponseState.EXECUTING in t}
    if into_executing != {ResponseState.AUTO_ALLOWED, ResponseState.APPROVED}:
        raise AssertionError(
            "EXECUTING must be reachable only from AUTO_ALLOWED or APPROVED; "
            f"found {sorted(s.value for s in into_executing)}"
        )

    # A denied or rejected response must be terminal.
    for blocked in BLOCKED_STATES:
        if RESPONSE_TRANSITIONS[blocked]:
            raise AssertionError(f"{blocked.value} must be terminal")

    # RESOLVED must follow recovery verification, not execution.
    into_resolved = {s for s, t in RESPONSE_TRANSITIONS.items() if ResponseState.RESOLVED in t}
    if into_resolved != {ResponseState.RECOVERED}:
        raise AssertionError(
            "RESOLVED must be reachable only from RECOVERED, so execution "
            f"alone cannot close a response; found {sorted(s.value for s in into_resolved)}"
        )


__all__ = [
    "BLOCKED_STATES",
    "RESPONSE_TRANSITIONS",
    "Actuator",
    "IllegalResponseTransition",
    "ResponseOrchestrator",
    "UnauthorisedExecution",
    "assert_response_transition",
    "validate_response_machine",
]
