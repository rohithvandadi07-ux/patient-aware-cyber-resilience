"""Read-only tool functions the five agents (L4) are allowed to call.

Architecture spec Section 11's agent table names these tools by name:
`get_logs`, `get_network_events`, `get_telemetry`, `get_device_state`,
`get_incident`, `evaluate_policy`. This module is the actual implementation
each agent calls through -- no agent gets a raw handle to a registry,
repository, or store; it only gets these functions, which is the structural
enforcement of "agents hold no execute capability" extended to "agents hold no
direct data-layer access either."

Every function here is read-only and returns only what some earlier layer
actually recorded (device registry snapshots, captured log records, stored
network events/telemetry, stored incidents) -- never fabricated evidence.
`evaluate_policy` used to be the one exception worth calling out: through
Phase 4 and 5 it was explicitly stubbed with `NotImplementedError`, because
the actual Policy Engine (Section 13) was Phase 6 work with its own
dedicated rule-table tests, not something to build hastily as a Phase 4 side
effect. Phase 6 now exists (`app/policy_engine/`, 100% measured branch
coverage) and `evaluate_policy` below is real wiring to it -- still
read-only, still never execution.

Phase 7 adds `get_recovery_results_for_incident`, reading the L8
`RecoveryResultRepository` (`app/recovery/`). It is not yet called by any
agent's prompt -- the Investigation Agent's tool list (Section 11) does not
name it, and wiring "show the Investigation Agent what the last recovery
check found" into its prompt is a decision for whatever later phase builds
the actual multi-agent re-investigation pipeline (still undecided, per
Section 11's own "orchestration mechanism [...] not decided yet"). It is
exposed now so that evidence is genuinely queryable rather than just
asserted to exist, not because it is already wired end to end.
"""

from app.iomt_simulator.registry import DeviceRegistry
from app.policy_engine.engine import PolicyEngine
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import CapturedLogRecord, LogCaptureHandler
from app.repositories.recovery_results import RecoveryResultRepository
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import ClinicalContext, RecoveryResult
from app.schemas.device import DeviceState
from app.schemas.enums import ResponseActionCategory
from app.schemas.events import NetworkEvent
from app.schemas.incident import Incident
from app.schemas.policy import PolicyDecision
from app.schemas.risk import RiskScore
from app.schemas.telemetry import TelemetryReading


class AgentToolkit:
    """Bundles the read-only stores/registries each agent's tool calls read
    from. Agents are constructed with one `AgentToolkit` and never see the
    individual stores directly -- this class is the actual tool allowlist
    boundary, not just documentation of one.
    """

    def __init__(
        self,
        device_registry: DeviceRegistry,
        incident_repository: IncidentRepository,
        network_event_store: NetworkEventStore,
        telemetry_store: TelemetryStore,
        log_handler: LogCaptureHandler,
        trace_recorder: AgentTraceRecorder,
        recovery_result_repository: RecoveryResultRepository | None = None,
    ) -> None:
        self._device_registry = device_registry
        self._incident_repository = incident_repository
        self._network_event_store = network_event_store
        self._telemetry_store = telemetry_store
        self._log_handler = log_handler
        self.trace_recorder = trace_recorder
        # Optional, defaulted (unlike every other store above) so Phase 4-6
        # callers/fixtures that construct AgentToolkit without this Phase 7
        # addition keep working unchanged -- a fresh, empty repository is a
        # safe default since "no recovery checks recorded yet" is exactly
        # what a new incident's toolkit should report.
        self._recovery_result_repository = recovery_result_repository or RecoveryResultRepository()

    @property
    def incident_repository(self) -> IncidentRepository:
        """Exposed (read/write) so callers outside the agent layer -- test
        fixtures, the scenario-to-incident wiring the API layer will need --
        can create/update incidents through the same repository the toolkit's
        own `get_incident` reads from, without reaching into a private
        attribute."""
        return self._incident_repository

    @property
    def network_event_store(self) -> NetworkEventStore:
        """Exposed so a scenario run's events can be recorded here, making
        `get_network_events` return real data instead of always being empty."""
        return self._network_event_store

    @property
    def telemetry_store(self) -> TelemetryStore:
        """Exposed for the same reason as `network_event_store`."""
        return self._telemetry_store

    @property
    def recovery_result_repository(self) -> RecoveryResultRepository:
        """Exposed so the Recovery Orchestrator (L8, `app/recovery/engine.py`)
        can record a `RecoveryResult` into the same repository
        `get_recovery_results_for_incident` reads from, without constructing
        a second, disconnected instance."""
        return self._recovery_result_repository

    def get_device_state(self, device_id: str) -> DeviceState:
        """Healthcare Context Agent's and Investigation Agent's tool (Section
        11). Wraps the same `DeviceRegistry` the simulator and `/devices` API
        use -- Section 9's "one source of truth," never a duplicated copy."""
        return self._device_registry.get_device_state(device_id)

    def get_network_events(self, device_id: str) -> list[NetworkEvent]:
        """Investigation Agent's and Recovery Verification Agent's tool.
        Returns whatever has actually been recorded into the
        `NetworkEventStore` for this device -- empty list if nothing has, not
        a fabricated event."""
        return self._network_event_store.query(device_id=device_id)

    def get_telemetry(self, device_id: str) -> list[TelemetryReading]:
        """Investigation Agent's tool. Same honesty rule as
        `get_network_events`: only what was actually recorded."""
        return self._telemetry_store.query(device_id=device_id)

    def get_logs(
        self, device_id: str | None = None, incident_id: str | None = None
    ) -> list[CapturedLogRecord]:
        """Investigation Agent's tool. Returns captured application log
        records -- see `app/repositories/log_capture.py` for why this reads
        real log records rather than a fabricated per-device log schema."""
        return self._log_handler.query(device_id=device_id, incident_id=incident_id)

    def get_incident(self, incident_id: str) -> Incident:
        """Threat Reasoning Agent's tool (direct single-incident lookup)."""
        return self._incident_repository.get(incident_id)

    def get_prior_incidents_for_device(self, device_id: str) -> list[Incident]:
        """Threat Reasoning Agent's tool for propagation context (Section 11:
        'prior incidents on same device')."""
        return self._incident_repository.list_for_device(device_id)

    def get_recovery_results_for_incident(self, incident_id: str) -> list[RecoveryResult]:
        """Not yet named in Section 11's agent table, and not yet called by
        any agent's prompt (see this module's docstring) -- added in Phase 7
        so the evidence a reopened incident carries (Section 7 step 12's
        "with the new evidence appended") is genuinely queryable through the
        same toolkit boundary every other read goes through, in the order
        each recovery check was recorded."""
        return self._recovery_result_repository.list_for_incident(incident_id)

    def evaluate_policy(
        self, risk_score: RiskScore, context: ClinicalContext
    ) -> dict[str, PolicyDecision]:
        """Response Planning Agent's tool: 'would this be auto-approved,'
        read-only, never execution (Section 11).

        Routes every action category actually scored in
        `risk_score.response_impact` through the real Policy Engine (L6,
        `app/policy_engine/engine.py`), returning one `PolicyDecision` per
        action category -- so the agent can see, before committing to a
        `recommended_action`, which of its candidates would be auto-approved
        and which would require human approval, and exactly which
        `policy_rule_id` would produce that outcome for each. This takes
        `risk_score` as a required parameter (not optional) deliberately:
        the Policy Engine routes on response_impact, so there is nothing to
        evaluate without one -- the caller (`response_planning.py`) is
        responsible for not calling this tool when it has no `RiskScore` yet,
        and for saying so honestly in its prompt instead.

        Raises `ValueError` (propagated from `PolicyEngine.evaluate_action`)
        if `risk_score.incident_id` and `context.incident_id` disagree --
        never silently routes decisions across two different incidents.
        """
        policy_engine = PolicyEngine()
        return {
            action_value: policy_engine.evaluate_action(
                risk_score, context, ResponseActionCategory(action_value)
            )
            for action_value in risk_score.response_impact
        }
