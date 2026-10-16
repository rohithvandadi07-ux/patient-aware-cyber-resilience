"""IncidentOrchestrator -- post-Phase-15: the real multi-agent pipeline
sequencer this project went a long time without, deliberately.

## Why this didn't exist until now

Three module docstrings elsewhere in this codebase record the same
reasoning for *not* building this earlier:

- `app/agents/llm_client.py`: no real LLM backend was wired in, "an open
  Phase 4+ decision ... made after the schemas above are implemented and
  testable against mocked LLM responses."
- `app/agents/README.md` / `app/api/agents.py`: "No orchestration layer
  sequences the five agents automatically yet ... An HTTP endpoint that
  'ran' an agent today could only do so against `MockLLMClient`'s
  pre-scripted responses, which would make the endpoint non-functional for
  any real caller -- building that now would be fabricating working
  functionality this project does not actually have."
- `app/recovery/engine.py`: `RecoveryOrchestrator.process_result` transitions
  a failed recovery to `IncidentStatus.REOPENED` -- Section 7 step 12's
  "failure re-opens it at step 4" -- but nothing ever watched for that status
  and re-invoked step 4. That was a real, disclosed gap (see the
  Post-Phase-15 gap audit in `claude/architecture-decisions.md`), not an
  oversight: there was no real LLM to re-invoke against yet either.

All three preconditions are now satisfied: the five agents' schemas/retry
policy are proven against `MockLLMClient` (every `app/agents/tests/test_*.py`
file, plus `tests/test_lifecycle_integration.py`'s real end-to-end chain);
`GeminiLLMClient` (`app/agents/llm_client.py`) is a real, callable LLM
backend, opt-in via `Settings.llm_backend="gemini"`; so an orchestrator that
sequences the agents automatically is no longer fabricating functionality --
it is real code calling other real code, the same calls
`tests/test_lifecycle_integration.py` already proved work when driven by
hand, step by step, over the HTTP API.

## What this class actually does

Replicates -- not reinvents -- the exact sequence
`tests/test_lifecycle_integration.py` drives manually, and calls the *same*
underlying services each HTTP route (`/risk-assessments`, `/responses/
proposed`, `/responses/executed`, `/recovery`) calls internally (the same
`PolicyEngine`, `ResponseOrchestrator`, `RecoveryOrchestrator`, the same
`app/blockchain/outbox.py` `enqueue_*` helpers) -- so a response produced by
this orchestrator leaves the exact same evidence trail (agent traces,
proposed/executed response records, outbox entries) as one driven by hand
over HTTP. This class holds no scoring, policy, or execution logic of its
own; it is sequencing and status bookkeeping only.

Closes three previously-disclosed gaps at once:

1. No orchestration layer sequenced the five agents automatically.
2. `IncidentStatus.INVESTIGATING` / `RISK_ASSESSED` / `RESPONSE_EXECUTING` /
   `RECOVERY_VERIFYING` were real enum members nothing in the live code path
   ever actually set (grep confirms only `DETECTED`, the five `*_STALLED`
   values, `RESOLVED`, and `REOPENED` were ever written by any caller before
   this module) -- this orchestrator is the first real writer of the other
   four, at the point in the pipeline each name describes.
3. A `REOPENED` incident was a dead end -- nothing re-triggered
   investigation. `run_investigation_cycle` now does, bounded by
   `max_reinvestigations` so a device that never recovers cannot loop
   forever; exhausting the budget leaves the incident `REOPENED` (visible,
   honest, not silently resolved) rather than retrying indefinitely.

## What this still does not do

- **Auto-approval is opt-in and explicitly logged as such.** When a
  `PolicyDecision` requires human approval and the caller passes
  `auto_approve=True`, this class fabricates an `ApprovalRecord` with
  `approver_identity="orchestrator-auto-approve"` and a `notes` field that
  says plainly this was not a real human sign-off. This exists only for
  automated research scenarios (the evaluation harness, demos) where no
  human is in the loop at all -- a real deployment should drive approval
  through the actual `/responses/executed` approval flow with a real
  identity, never this flag. Default is `False`.
- **Does not invent evidence.** `affected_devices` passed to the Healthcare
  Context Agent comes from the Investigation Agent's own
  `InvestigationReport.affected_devices`, falling back to the single
  `device_id` the caller supplied only when the agent reported none -- never
  a guessed device list.
- **Does not retry a stalled agent step itself.** `generate_validated`
  already retries once at the LLM-call level (its own, separate policy);
  if an agent still stalls after that, this orchestrator stops and reports
  the stall status rather than retrying the whole cycle -- a schema-invalid
  LLM response is a different failure mode than "recovery check found
  containment failed," and only the latter is what Section 7 step 12's
  re-investigation loop is about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.agents.base import AgentStalledError
from app.agents.healthcare_context import assess_clinical_context
from app.agents.investigation import investigate
from app.agents.llm_client import LLMClient
from app.agents.recovery_verification import verify_recovery
from app.agents.response_planning import plan_response
from app.agents.threat_reasoning import assess_threat
from app.agents.tools import AgentToolkit
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import (
    OutboxRepository,
    enqueue_approval,
    enqueue_decision,
    enqueue_recovery,
    enqueue_response,
)
from app.core.timing import StageTimings
from app.policy_engine.engine import PolicyEngine
from app.recovery.engine import InconsistentRecoveryResultError, RecoveryOrchestrator
from app.repositories.incidents import IncidentRepository
from app.repositories.responses import ExecutedResponseRepository, ProposedResponseRepository
from app.response_engine.orchestrator import (
    ApprovalRequiredError,
    ResponseOrchestrator,
    ResponseRejectedError,
)
from app.risk_engine.model import RiskModel
from app.schemas.agents import RecoveryResult
from app.schemas.blockchain import DecisionProvenance, RecoveryProvenance, ResponseProvenance
from app.schemas.enums import ApprovalDecision, IncidentStatus
from app.schemas.policy import PolicyDecision
from app.schemas.response import ApprovalRecord, ExecutedResponse

_AUTO_APPROVE_IDENTITY = "orchestrator-auto-approve"


@dataclass
class CycleResult:
    """What one `run_investigation_cycle` call produced, end to end (or as
    far as it got before stopping). `history` is a human-readable trace of
    every step attempted, in order -- intended for the Agent Activity panel
    / API response, not for parsing."""

    incident_id: str
    final_status: str
    reinvestigation_count: int
    history: list[str] = field(default_factory=list)
    awaiting_approval_decision: PolicyDecision | None = None
    executed: ExecutedResponse | None = None
    recovery: RecoveryResult | None = None
    # Wall-clock milliseconds per pipeline stage, summed across re-investigations.
    # In-process compute only: with the default mock LLM the agent stages are
    # near-zero, and a real LLM call, queueing and human approval are NOT in it.
    stage_timings_ms: dict[str, float] = field(default_factory=dict)


class IncidentOrchestrator:
    """Sequences the five agents and the L5-L8 deterministic services for
    one incident. See module docstring for the full rationale."""

    def __init__(
        self,
        *,
        client: LLMClient,
        toolkit: AgentToolkit,
        incident_repository: IncidentRepository,
        proposed_response_repository: ProposedResponseRepository,
        executed_response_repository: ExecutedResponseRepository,
        response_orchestrator: ResponseOrchestrator,
        recovery_orchestrator: RecoveryOrchestrator,
        outbox_repository: OutboxRepository,
        risk_model: RiskModel,
        max_reinvestigations: int = 2,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._client = client
        self._toolkit = toolkit
        self._incident_repository = incident_repository
        self._proposed_repo = proposed_response_repository
        self._executed_repo = executed_response_repository
        self._response_orchestrator = response_orchestrator
        self._recovery_orchestrator = recovery_orchestrator
        self._outbox_repo = outbox_repository
        self._risk_model = risk_model
        self._max_reinvestigations = max_reinvestigations
        self._policy_engine = policy_engine or PolicyEngine()
        self._timings = StageTimings()

    def run_investigation_cycle(
        self, incident_id: str, device_id: str, *, auto_approve: bool = False
    ) -> CycleResult:
        """Entry point. Runs investigate -> threat -> clinical context ->
        response planning -> risk scoring -> policy decision -> (approval
        gate) -> execution -> recovery verification -> recovery routing,
        and re-enters at investigation if recovery routes to `REOPENED`,
        up to `max_reinvestigations` times."""
        self._timings = StageTimings()
        result = self._run(incident_id, device_id, auto_approve=auto_approve, reinvestigation_count=0)
        result.stage_timings_ms = self._timings.as_dict()
        return result

    def _run(
        self, incident_id: str, device_id: str, *, auto_approve: bool, reinvestigation_count: int
    ) -> CycleResult:
        history: list[str] = []
        if reinvestigation_count > 0:
            history.append(f"re-investigation attempt {reinvestigation_count}")

        self._incident_repository.update_status(incident_id, IncidentStatus.INVESTIGATING)
        try:
            with self._timings.stage("investigation"):
                report = investigate(
                    self._client, self._toolkit, incident_id=incident_id, device_id=device_id
                )
            history.append("investigation: ok")

            with self._timings.stage("threat_reasoning"):
                threat = assess_threat(self._client, self._toolkit, report=report, device_id=device_id)
            history.append(f"threat_reasoning: ok (attack_type={threat.attack_type.value})")

            affected = report.affected_devices or [device_id]
            with self._timings.stage("healthcare_context"):
                context = assess_clinical_context(
                    self._client, self._toolkit, incident_id=incident_id, affected_devices=affected
                )
            history.append("healthcare_context: ok")

            with self._timings.stage("response_planning"):
                proposal = plan_response(
                    self._client, self._toolkit, threat=threat, context=context, risk_score=None
                )
            history.append(f"response_planning: ok (recommended={proposal.recommended_action.value})")
        except AgentStalledError as exc:
            history.append(f"stalled: {exc}")
            return CycleResult(
                incident_id=incident_id,
                final_status=exc.stall_status.value,
                reinvestigation_count=reinvestigation_count,
                history=history,
            )

        self._incident_repository.update_status(incident_id, IncidentStatus.RISK_ASSESSED)
        with self._timings.stage("risk_engine"):
            risk_score = self._risk_model.calculate_risk(threat, context, proposal.candidate_actions)
        history.append(
            f"risk_engine: ok (cyber_risk={risk_score.cyber_risk:.2f}, "
            f"clinical_risk={risk_score.clinical_risk:.2f})"
        )

        # The Threat Reasoning Agent's confidence stands in for the detector's here
        # (the agent is given the DetectionEvent as evidence). It is only consulted
        # when the opt-in confidence gate is enabled, and can only demote autonomy
        # to human approval, never grant it.
        with self._timings.stage("policy_engine"):
            decision = self._policy_engine.evaluate(
                risk_score, proposal, context, detection_confidence=threat.confidence
            )
        self._proposed_repo.put(decision)
        enqueue_decision(
            self._outbox_repo,
            DecisionProvenance(
                incident_id=decision.incident_id,
                risk_score_hash=hash_payload(risk_score),
                policy_rule_id=decision.policy_rule_id,
                recommended_action=decision.chosen_action,
            ),
        )
        history.append(
            f"policy_engine: decision={decision.chosen_action.value} "
            f"requires_human_approval={decision.requires_human_approval}"
        )

        if decision.requires_human_approval and not auto_approve:
            self._incident_repository.update_status(incident_id, IncidentStatus.AWAITING_APPROVAL)
            history.append("stopping: awaiting human approval (auto_approve=False)")
            return CycleResult(
                incident_id=incident_id,
                final_status=IncidentStatus.AWAITING_APPROVAL.value,
                reinvestigation_count=reinvestigation_count,
                awaiting_approval_decision=decision,
                history=history,
            )

        approval: ApprovalRecord | None = None
        if decision.requires_human_approval and auto_approve:
            approval = ApprovalRecord(
                incident_id=incident_id,
                approver_identity=_AUTO_APPROVE_IDENTITY,
                decision=ApprovalDecision.APPROVED,
                timestamp=datetime.now(UTC),
                notes=(
                    "Auto-approved by IncidentOrchestrator (auto_approve=True) for an automated "
                    "research/evaluation run -- NOT a real human sign-off. A real deployment must "
                    "drive this through the real approval flow with a real approver_identity."
                ),
            )
            history.append("auto-approved (research/evaluation mode -- not a real human)")

        self._incident_repository.update_status(incident_id, IncidentStatus.RESPONSE_EXECUTING)
        try:
            with self._timings.stage("response_execution"):
                executed = self._response_orchestrator.execute(decision, approval=approval)
        except (ApprovalRequiredError, ResponseRejectedError, ValueError, NotImplementedError) as exc:
            history.append(f"response_execution: failed: {exc}")
            return CycleResult(
                incident_id=incident_id,
                final_status="execution_failed",
                reinvestigation_count=reinvestigation_count,
                history=history,
            )

        self._executed_repo.record(executed)
        self._proposed_repo.remove(incident_id)
        enqueue_response(
            self._outbox_repo,
            ResponseProvenance(
                incident_id=executed.incident_id,
                action_taken=executed.action_taken,
                executed_by=executed.executed_by,
                timestamp=executed.timestamp,
            ),
        )
        if approval is not None:
            from app.schemas.blockchain import ApprovalProvenance

            enqueue_approval(
                self._outbox_repo,
                ApprovalProvenance(
                    incident_id=approval.incident_id,
                    approver_identity=approval.approver_identity,
                    decision=approval.decision,
                    timestamp=approval.timestamp,
                ),
            )
        history.append(f"response_execution: ok (action_taken={executed.action_taken.value})")

        self._incident_repository.update_status(incident_id, IncidentStatus.RECOVERY_VERIFYING)
        response_id = f"{incident_id}-response-{reinvestigation_count + 1}"
        try:
            with self._timings.stage("recovery_verification"):
                recovery_result = verify_recovery(
                    self._client,
                    self._toolkit,
                    incident_id=incident_id,
                    response_id=response_id,
                    device_id=device_id,
                )
        except AgentStalledError as exc:
            history.append(f"stalled: {exc}")
            return CycleResult(
                incident_id=incident_id,
                final_status=exc.stall_status.value,
                reinvestigation_count=reinvestigation_count,
                executed=executed,
                history=history,
            )
        history.append(
            f"recovery_verification: ok (recovery_succeeded={recovery_result.recovery_succeeded}, "
            f"reinvestigation_required={recovery_result.reinvestigation_required})"
        )

        try:
            with self._timings.stage("recovery_routing"):
                incident = self._recovery_orchestrator.process_result(recovery_result)
        except InconsistentRecoveryResultError as exc:
            history.append(f"recovery routing refused (inconsistent result): {exc}")
            return CycleResult(
                incident_id=incident_id,
                final_status="recovery_inconsistent",
                reinvestigation_count=reinvestigation_count,
                executed=executed,
                recovery=recovery_result,
                history=history,
            )

        enqueue_recovery(
            self._outbox_repo,
            RecoveryProvenance(
                incident_id=recovery_result.incident_id,
                recovery_verified=recovery_result.recovery_succeeded,
                residual_threats_hash=hash_payload(recovery_result.residual_threats)
                if recovery_result.residual_threats
                else None,
            ),
        )
        history.append(f"recovery: incident status -> {incident.status.value}")

        if incident.status == IncidentStatus.REOPENED:
            if reinvestigation_count >= self._max_reinvestigations:
                history.append(
                    f"re-investigation budget exhausted ({self._max_reinvestigations}) -- "
                    "stopping; incident remains REOPENED rather than retrying indefinitely"
                )
                return CycleResult(
                    incident_id=incident_id,
                    final_status=IncidentStatus.REOPENED.value,
                    reinvestigation_count=reinvestigation_count,
                    executed=executed,
                    recovery=recovery_result,
                    history=history,
                )
            return self._run(
                incident_id,
                device_id,
                auto_approve=auto_approve,
                reinvestigation_count=reinvestigation_count + 1,
            )

        return CycleResult(
            incident_id=incident_id,
            final_status=incident.status.value,
            reinvestigation_count=reinvestigation_count,
            executed=executed,
            recovery=recovery_result,
            history=history,
        )
