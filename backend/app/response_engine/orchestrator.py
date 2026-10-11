"""ResponseOrchestrator -- L7, the only service that actually executes a
response action.

Architecture spec Section 7 (data flow), steps 9-11: the Policy Engine (L6)
decides routing; if `requires_human_approval` is true, the SOC dashboard
(L10) surfaces the incident and "a human approves or rejects -- that
decision is written back to L6"; only then does "the Response Orchestrator
(L7) execute[] only the action L6 has cleared -- calling the simulator's own
command interface, never touching real infrastructure." Section 3's
agent/policy boundary decision states the same thing from the other
direction: "only the Response Orchestrator (a separate, non-agentic,
deterministic service) calls execution tools."

This module enforces that structurally, not just by convention:
`ResponseOrchestrator.execute` is the only function anywhere in this
codebase that calls a `SimulatedDevice` mutation method (`isolate`,
`power_off`, `set_operational_state`) on the strength of a `PolicyDecision`
-- no agent, and no other service, holds that call.

**Honest execution scope (anti-fabrication):** the simulator (Phase 2,
`app/iomt_simulator/device.py`) has a real mechanism for exactly three
things: cutting network access (`isolate`), powering off (`power_off`,
added in Phase 6 alongside `OperationalState.OFF`), and resetting to normal
operation. It has no concept of a session, a credential, a backup, or a
failover target anywhere in its state model. Rather than inventing one here
as a side effect of wiring the orchestrator -- which would mean
`REVOKE_SESSION`/`ROTATE_CREDENTIALS`/`ACTIVATE_BACKUP`/`FAILOVER` silently
"execute" against nothing real -- `_apply_action` below raises
`NotImplementedError` for those four categories, naming exactly what
mechanism is missing. This is the same stub-rather-than-fabricate pattern as
`training.py`'s `load_real_dataset` and Phase 4's original
`AgentToolkit.evaluate_policy` stub.

**Why the five isolate-family categories collapse to one simulator call:**
`BLOCK_TRAFFIC`, `RESTRICT_COMMUNICATION`, `ISOLATE_NON_CRITICAL`,
`ISOLATE_CRITICAL`, and `QUARANTINE_SEGMENT` are, to the Policy Engine's rule
table (`app/policy_engine/rules.py`) and the Risk Engine's scoring
(`app/risk_engine/rules.py`), five distinct categories with different
clinical-impact weight -- but the simulator has no network-topology model
granular enough to tell "block this one traffic flow" apart from "isolate
this whole segment." All five produce the same observable simulator effect
(`SimulatedDevice.isolate()`): network_state="isolated",
operational_state=ISOLATED. This is documented here, not silently
collapsed, so a reader auditing "does the orchestrator actually do what the
rule table implies" can see the real granularity limit.
"""

from datetime import UTC, datetime

from app.iomt_simulator.device import SimulatedDevice
from app.iomt_simulator.registry import DeviceRegistry
from app.repositories.incidents import IncidentRepository
from app.schemas.device import OperationalState
from app.schemas.enums import ApprovalDecision, ResponseActionCategory
from app.schemas.policy import PolicyDecision
from app.schemas.response import ApprovalRecord, ExecutedResponse

# Section 13's rule table operates on these five as distinct categories;
# the simulator cannot distinguish their effects (see module docstring).
_ISOLATION_FAMILY = frozenset(
    {
        ResponseActionCategory.BLOCK_TRAFFIC,
        ResponseActionCategory.RESTRICT_COMMUNICATION,
        ResponseActionCategory.ISOLATE_NON_CRITICAL,
        ResponseActionCategory.ISOLATE_CRITICAL,
        ResponseActionCategory.QUARANTINE_SEGMENT,
    }
)

# Categories with no corresponding mechanism anywhere in the simulator's
# state model (no session, credential, backup, or failover concept exists).
# Listed explicitly, rather than reached via an `else` branch, so this set
# is itself the honest inventory of what this orchestrator cannot yet do --
# reviewable without reading `_apply_action`'s control flow.
_NO_SIMULATOR_MECHANISM_ACTIONS = frozenset(
    {
        ResponseActionCategory.REVOKE_SESSION,
        ResponseActionCategory.ROTATE_CREDENTIALS,
        ResponseActionCategory.ACTIVATE_BACKUP,
        ResponseActionCategory.FAILOVER,
    }
)

# Same exhaustiveness pattern as risk_engine/rules.py's disruption-tier
# assertion: every ResponseActionCategory must fall into exactly one of
# {SHUTDOWN} | isolation family | {RESTART_SERVICE} | no-mechanism set, so
# `_apply_action` below never needs a catch-all `else` whose branch no test
# could ever reach.
assert (
    {ResponseActionCategory.SHUTDOWN, ResponseActionCategory.RESTART_SERVICE}
    | _ISOLATION_FAMILY
    | _NO_SIMULATOR_MECHANISM_ACTIONS
) == set(ResponseActionCategory), "every ResponseActionCategory must be classified in orchestrator.py"


class ApprovalRequiredError(Exception):
    """Raised by `execute` when `policy_decision.requires_human_approval` is
    true and no `ApprovalRecord` was supplied. The orchestrator never
    executes a human-approval-required action on an assumed or implicit
    approval."""


class ResponseRejectedError(Exception):
    """Raised by `execute` when the supplied `ApprovalRecord.decision` is
    `REJECTED` -- the orchestrator must not execute, and must not silently
    no-op either; the caller needs to know the action was blocked, not
    merely skipped."""


class ResponseOrchestrator:
    """L7: the only service with a handle on `SimulatedDevice` mutation
    methods for the purpose of carrying out a cleared response."""

    def __init__(self, device_registry: DeviceRegistry, incident_repository: IncidentRepository) -> None:
        self._device_registry = device_registry
        self._incident_repository = incident_repository

    def execute(
        self, policy_decision: PolicyDecision, approval: ApprovalRecord | None = None
    ) -> ExecutedResponse:
        """Execute `policy_decision.chosen_action` -- but only once the
        approval-gating below is satisfied.

        - If `requires_human_approval` is false: executes immediately,
          `executed_by="system"` (Section 7 step 9's "auto-approved" path),
          ignoring any `approval` passed (it is not needed and not checked).
        - If `requires_human_approval` is true: raises `ApprovalRequiredError`
          if `approval` is `None`; raises `ValueError` if
          `approval.incident_id` does not match `policy_decision.incident_id`
          (refusing to let an approval for one incident authorize a response
          on another); raises `ResponseRejectedError` if
          `approval.decision == REJECTED`; otherwise executes with
          `executed_by=approval.approver_identity` (Section 7 step 10: "that
          decision is written back to L6" before L7 may act).

        Looks up the incident's `device_id` via `IncidentRepository` (raises
        `IncidentNotFoundError` if unknown) and the live `SimulatedDevice` via
        `DeviceRegistry` (raises `DeviceNotFoundError` if unknown) -- this is
        why the orchestrator is constructed with both, rather than taking a
        device directly: `PolicyDecision` only carries `incident_id`.
        """
        executed_by = self._check_approval_gate(policy_decision, approval)

        incident = self._incident_repository.get(policy_decision.incident_id)
        device = self._device_registry.get(incident.device_id)
        _apply_action(device, policy_decision.chosen_action)

        return ExecutedResponse(
            incident_id=policy_decision.incident_id,
            action_taken=policy_decision.chosen_action,
            executed_by=executed_by,
            timestamp=datetime.now(UTC),
            chain_tx_id=None,
        )

    @staticmethod
    def _check_approval_gate(
        policy_decision: PolicyDecision, approval: ApprovalRecord | None
    ) -> str:
        """Returns the `executed_by` identity once the gate is satisfied, or
        raises. Pulled out of `execute` so the gating logic -- the one part
        of this class that actually enforces Section 13's authority, as
        opposed to merely wiring to the simulator -- is its own small,
        independently-testable unit."""
        if not policy_decision.requires_human_approval:
            return "system"

        if approval is None:
            raise ApprovalRequiredError(
                f"PolicyDecision for incident {policy_decision.incident_id!r} "
                f"(rule={policy_decision.policy_rule_id}) requires human approval, and none was "
                "provided -- refusing to execute on an assumed approval"
            )
        if approval.incident_id != policy_decision.incident_id:
            raise ValueError(
                f"approval.incident_id ({approval.incident_id!r}) and policy_decision.incident_id "
                f"({policy_decision.incident_id!r}) must match -- refusing to let an approval for "
                "one incident authorize a response on another"
            )
        if approval.decision != ApprovalDecision.APPROVED:
            raise ResponseRejectedError(
                f"Approval for incident {policy_decision.incident_id!r} was "
                f"{approval.decision.value!r}, not approved -- refusing to execute"
            )
        return approval.approver_identity


def _apply_action(device: SimulatedDevice, action_category: ResponseActionCategory) -> None:
    """The real simulator mutation for one cleared action, or a clear
    `NotImplementedError` naming the missing mechanism. See the module
    docstring for why each branch maps the way it does."""
    if action_category == ResponseActionCategory.SHUTDOWN:
        device.power_off()
        return

    if action_category in _ISOLATION_FAMILY:
        device.isolate()
        return

    if action_category == ResponseActionCategory.RESTART_SERVICE:
        # Reset to normal operation -- the simulator's equivalent of
        # restarting a stuck/degraded service, since there is no real
        # process to restart.
        device.set_network_state("connected")
        device.set_operational_state(OperationalState.IDLE)
        return

    # The module-level assertion above guarantees action_category is in
    # _NO_SIMULATOR_MECHANISM_ACTIONS at this point -- no catch-all needed.
    raise NotImplementedError(
        f"{action_category.value} has no corresponding mechanism in the simulator's state "
        "model (no session, credential, backup, or failover concept exists in "
        "app/iomt_simulator/device.py) -- not something to fake here. See this module's "
        "docstring."
    )
