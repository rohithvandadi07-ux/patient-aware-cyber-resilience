"""Device registry — the single source of truth for device state.

Architecture spec Section 9: "The simulator exposes its device registry and
current state through the same `get_device_state` tool the Healthcare Context
Agent calls [...] there is one source of truth for 'is this device
patient-dependent right now,' not a duplicated copy in the agent layer."

In Phase 2 this is an in-memory registry. When Phase 4's agent tool layer is
built, `get_device_state(device_id)` wraps this same registry rather than a
second copy — the function signature below is intentionally already shaped like
that future tool call.
"""

from app.iomt_simulator.device import SimulatedDevice
from app.schemas.device import DeviceState


class DeviceNotFoundError(KeyError):
    """Raised when a device_id has no corresponding registered device."""


class DeviceRegistry:
    def __init__(self) -> None:
        self._devices: dict[str, SimulatedDevice] = {}

    def register(self, device: SimulatedDevice) -> None:
        if device.device_id in self._devices:
            raise ValueError(f"Device '{device.device_id}' is already registered")
        self._devices[device.device_id] = device

    def get(self, device_id: str) -> SimulatedDevice:
        try:
            return self._devices[device_id]
        except KeyError as exc:
            raise DeviceNotFoundError(device_id) from exc

    def get_device_state(self, device_id: str) -> DeviceState:
        """The read-only, schema-shaped accessor every later layer (Healthcare
        Context Agent, API routes) is expected to call instead of reaching into
        `get()` and the raw `SimulatedDevice` object."""
        return self.get(device_id).snapshot()

    def list_devices(self) -> list[DeviceState]:
        return [device.snapshot() for device in self._devices.values()]

    def all_devices(self) -> list[SimulatedDevice]:
        """The live, mutable device objects — not their snapshots. For
        internal simulator use (e.g. ScenarioRunner ticking every device
        forward), not for the agent/API read path, which should use
        `get_device_state`/`list_devices` instead."""
        return list(self._devices.values())

    def __len__(self) -> int:
        return len(self._devices)
