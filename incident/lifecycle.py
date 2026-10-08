"""Incident lifecycle state machine.

Transitions are declared as data and validated, so an illegal transition
raises rather than silently corrupting an incident's history. This matters
because the incident state drives the whole closed loop: a response
orchestrator that can jump from DETECTED to RESOLVED without passing
through recovery verification would make the resilience metrics meaningless.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.domain.enums import IncidentState as S

#: Legal transitions. Mandated by the specification's lifecycle, plus the
#: failure and re-investigation edges the closed loop requires.
TRANSITIONS: dict[S, frozenset[S]] = {
    S.DETECTED: frozenset({S.INVESTIGATING, S.FAILED}),
    S.INVESTIGATING: frozenset({S.ASSESSED, S.FAILED}),
    S.ASSESSED: frozenset({S.PLANNING, S.FAILED}),
    S.PLANNING: frozenset(
        {
            S.AWAITING_APPROVAL,
            S.APPROVED,  # policy auto-allowed
            S.RESOLVED,  # monitor-only outcome needs no execution
            S.FAILED,
        }
    ),
    S.AWAITING_APPROVAL: frozenset({S.APPROVED, S.FAILED, S.PLANNING}),
    S.APPROVED: frozenset({S.EXECUTING, S.FAILED}),
    S.EXECUTING: frozenset({S.RECOVERING, S.FAILED}),
    S.RECOVERING: frozenset({S.RESOLVED, S.REINVESTIGATING, S.FAILED}),
    S.REINVESTIGATING: frozenset({S.ASSESSED, S.PLANNING, S.FAILED}),
    # Terminal states
    S.RESOLVED: frozenset(),
    S.FAILED: frozenset(),
}

TERMINAL_STATES: frozenset[S] = frozenset({S.RESOLVED, S.FAILED})

#: States in which the incident is waiting on a human.
BLOCKED_ON_HUMAN: frozenset[S] = frozenset({S.AWAITING_APPROVAL})


class IllegalTransition(ValueError):
    """Raised when an incident is moved along an undeclared edge."""


@dataclass(frozen=True)
class TransitionCheck:
    allowed: bool
    reason: str = ""


def can_transition(current: S, target: S) -> TransitionCheck:
    if current in TERMINAL_STATES:
        return TransitionCheck(
            False,
            f"{current.value} is terminal; an incident cannot leave it. "
            "Open a new incident instead of reviving a closed one.",
        )
    allowed = TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        return TransitionCheck(
            False,
            f"{current.value} -> {target.value} is not a legal transition. "
            f"Legal from {current.value}: "
            f"{sorted(s.value for s in allowed) or 'none'}.",
        )
    return TransitionCheck(True)


def assert_transition(current: S, target: S) -> None:
    check = can_transition(current, target)
    if not check.allowed:
        raise IllegalTransition(check.reason)


def reachable_from(state: S) -> frozenset[S]:
    """All states reachable from ``state``, for validation and docs."""
    seen: set[S] = set()
    frontier = [state]
    while frontier:
        s = frontier.pop()
        for nxt in TRANSITIONS.get(s, frozenset()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return frozenset(seen)


def validate_machine() -> None:
    """Structural invariants, asserted at import time by the test suite."""
    for state in S:
        if state not in TRANSITIONS:
            raise AssertionError(f"state {state.value} has no transition entry")
    # Every non-terminal state must be able to reach a terminal state, or an
    # incident could be stranded forever and the MTTR metric would be
    # undefined.
    for state in S:
        if state in TERMINAL_STATES:
            continue
        if not (reachable_from(state) & TERMINAL_STATES):
            raise AssertionError(
                f"{state.value} cannot reach a terminal state; incidents could "
                "be stranded and MTTR would be undefined"
            )
    # Recovery must be the only route to RESOLVED other than a
    # monitor-only plan, so the closed loop cannot be short-circuited.
    into_resolved = {s for s, targets in TRANSITIONS.items() if S.RESOLVED in targets}
    if into_resolved != {S.RECOVERING, S.PLANNING}:
        raise AssertionError(
            "RESOLVED must be reachable only from RECOVERING (verified) or "
            f"PLANNING (monitor-only); found {sorted(s.value for s in into_resolved)}"
        )


__all__ = [
    "BLOCKED_ON_HUMAN",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "IllegalTransition",
    "TransitionCheck",
    "assert_transition",
    "can_transition",
    "reachable_from",
    "validate_machine",
]
