"""Simulated IoMT device state machines.

Architecture spec Section 9: each device is a state machine, not a static record.
`SimulatedDevice` holds the identity and clinical attributes shared by every
device type (criticality, patient dependency, operational/network state) and
exposes a `snapshot()` that converts directly to the shared `DeviceState` schema —
the same shape the Healthcare Context Agent will read in later phases via
`get_device_state` (Section 2.3 of this phase).

Telemetry generation lives in `telemetry.py`, not here — a device's *state*
(is it on, is it connected, is a patient depending on it) is a different concern
from the *readings* it produces moment to moment, and keeping them separate is
what lets the ScenarioRunner mutate network/operational state without having to
know anything about respiratory waveforms or drip rates.
"""

from dataclasses import dataclass, field

from app.schemas.device import DeviceState, DeviceType, OperationalState
from app.schemas.enums import DeviceCriticality


class ActionPreconditionError(Exception):
    """A response action cannot take effect because the thing it acts on does not exist
    (no active session to revoke, no backup to activate, no standby to fail over to).
    Raised instead of reporting a success that changed nothing."""


@dataclass
class SimulatedDevice:
    """Base state machine for a simulated IoMT device.

    Subclasses (InfusionPump, Ventilator, EcgMonitor) fix `device_type` and may
    add device-specific attributes, but all state transitions and the
    snapshot-to-schema conversion are handled here so there is exactly one place
    that defines what "the device's current state" means.
    """

    device_id: str
    device_type: DeviceType
    criticality: DeviceCriticality
    patient_dependency: bool
    synthetic_patient_id: str | None = None
    operational_state: OperationalState = OperationalState.IDLE
    network_state: str = "connected"

    # Modelled resilience state (M4). Simulated effects, not real infrastructure: they give
    # REVOKE_SESSION / ROTATE_CREDENTIALS / ACTIVATE_BACKUP / FAILOVER something real to change.
    active_sessions: list[str] = field(default_factory=list)
    credential_version: int = 1
    backup_available: bool = False
    backup_active: bool = False
    standby_unit_id: str | None = None
    serving_unit: str | None = None

    # Internal transition log, useful for scenario/test assertions without
    # needing a separate event store during Phase 2. Not settable by callers.
    _state_history: list[tuple[OperationalState, str]] = field(
        default_factory=list, repr=False, init=False
    )

    def set_operational_state(self, new_state: OperationalState) -> None:
        self._state_history.append((new_state, self.network_state))
        self.operational_state = new_state

    def set_network_state(self, new_state: str) -> None:
        self._state_history.append((self.operational_state, new_state))
        self.network_state = new_state

    def isolate(self) -> None:
        """Simulate a network isolation response action (Section 13's
        ISOLATE_NON_CRITICAL / ISOLATE_CRITICAL categories) by cutting network
        state and marking operational state ISOLATED. (Docstring corrected in
        Phase 6: an earlier version of this docstring claimed operational
        state was left untouched "so the device keeps running clinically" --
        that was never actually true of the code below, which has always set
        `operational_state` to `ISOLATED` too, and `test_device.py`'s
        `test_isolate_cuts_network_and_operational_state` has always asserted
        exactly that. This was a stale comment, not a behavior change.)"""
        self.set_network_state("isolated")
        self.set_operational_state(OperationalState.ISOLATED)

    def power_off(self) -> None:
        """Simulate a genuine SHUTDOWN response action (Section 13's
        `ResponseActionCategory.SHUTDOWN`) added in Phase 6, now that
        `OperationalState.OFF` exists to represent it honestly. Distinct from
        `isolate()`: this is a full power-down, not a network cut -- the
        device stops running clinically, which is exactly why Section 13's
        unconditional-approval rule singles SHUTDOWN out for a
        patient-dependent device, and why the Response Orchestrator (L7,
        Phase 6/7) must never call this without a `PolicyDecision` that was
        actually routed through human approval when required. Network state
        is set to "offline", not "isolated" -- a powered-off device has no
        network connection to isolate, and reusing isolate()'s string would
        make a state-history diff unable to tell a SHUTDOWN from an
        isolation apart by network_state alone."""
        self.set_network_state("offline")
        self.set_operational_state(OperationalState.OFF)

    def revoke_sessions(self) -> int:
        # Terminate every active session. Refuses, rather than reporting success, when
        # there is nothing to revoke.
        if not self.active_sessions:
            raise ActionPreconditionError(f"{self.device_id}: no active sessions to revoke")
        revoked = len(self.active_sessions)
        self.active_sessions.clear()
        return revoked

    def rotate_credentials(self) -> int:
        # New credential version. Sessions established with the old credential end, which is
        # the second-order effect the Risk Engine's caution margin refers to.
        self.credential_version += 1
        self.active_sessions.clear()
        return self.credential_version

    def activate_backup(self) -> None:
        if not self.backup_available:
            raise ActionPreconditionError(f"{self.device_id}: no backup path is available to activate")
        if self.backup_active:
            raise ActionPreconditionError(f"{self.device_id}: the backup path is already active")
        self.backup_active = True

    def fail_over(self) -> str:
        # Move service to the standby unit and take this unit out of the clinical path.
        if self.standby_unit_id is None:
            raise ActionPreconditionError(f"{self.device_id}: no standby unit is configured")
        if self.serving_unit is not None:
            raise ActionPreconditionError(
                f"{self.device_id}: already failed over to {self.serving_unit}"
            )
        self.serving_unit = self.standby_unit_id
        self.isolate()
        return self.serving_unit

    def snapshot(self) -> DeviceState:
        """Convert current state to the shared DeviceState schema."""
        return DeviceState(
            device_id=self.device_id,
            device_type=self.device_type,
            criticality=self.criticality,
            patient_dependency=self.patient_dependency,
            synthetic_patient_id=self.synthetic_patient_id,
            operational_state=self.operational_state,
            network_state=self.network_state,
            active_sessions=list(self.active_sessions),
            credential_version=self.credential_version,
            backup_available=self.backup_available,
            backup_active=self.backup_active,
            standby_unit_id=self.standby_unit_id,
            serving_unit=self.serving_unit,
        )


@dataclass
class InfusionPump(SimulatedDevice):
    device_type: DeviceType = field(default=DeviceType.INFUSION_PUMP, init=False)
    flow_rate_ml_per_hr: float = 100.0
    medication: str = "normal_saline"


@dataclass
class Ventilator(SimulatedDevice):
    device_type: DeviceType = field(default=DeviceType.VENTILATOR, init=False)
    respiratory_rate_bpm: float = 16.0
    tidal_volume_ml: float = 450.0


@dataclass
class EcgMonitor(SimulatedDevice):
    device_type: DeviceType = field(default=DeviceType.ECG_MONITOR, init=False)
    heart_rate_bpm: float = 72.0
    spo2_percent: float = 98.0
