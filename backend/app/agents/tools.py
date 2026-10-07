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
`evaluate_policy` is the one exception worth calling out: the actual Policy
Engine (Section 13) is Phase 6 work with its own dedicated rule-table tests,
not something to build hastily as a Phase 4 side effect, so it is explicitly
stubbed with `NotImplementedError` here rather than faked -- see that
function's docstring.
"""

from app.iomt_simulator.registry import DeviceRegistry
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import CapturedLogRecord, LogCaptureHandler
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.device import DeviceState
from app.schemas.events import NetworkEvent
from app.schemas.incident import Incident
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
    ) -> None:
        self._device_registry = device_registry
        self._incident_repository = incident_repository
        self._network_event_store = network_event_store
        self._telemetry_store = telemetry_store
        self._log_handler = log_handler
        self.trace_recorder = trace_recorder

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

    def evaluate_policy(self) -> None:
        """Response Planning Agent's tool: 'would this be auto-approved,'
        read-only, never execution (Section 11).

        NOT IMPLEMENTED: the actual Policy Engine rule table (Section 13's
        autonomous/conditional/human-approval thresholds) is Phase 6 work,
        gated on its own dedicated test suite ('100% of its branches covered
        by tests' per Section 19's Phase 6 gate). Building a quick version of
        it here, as a side effect of wiring the Response Planning Agent's
        tool allowlist, would mean the actual safety-routing logic first
        exists un-reviewed and under-tested -- exactly what Section 19 is
        structured to prevent. The Response Planning Agent (Phase 4.7) is
        built to call this and handle the NotImplementedError by omitting a
        policy pre-check from its reasoning, not by receiving a fabricated
        answer.
        """
        raise NotImplementedError(
            "evaluate_policy is not implemented yet -- the Policy Engine (Section 13) "
            "is Phase 6 work with its own dedicated rule-table tests. See "
            "app/policy_engine/README.md."
        )
