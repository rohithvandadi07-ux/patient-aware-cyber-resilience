"""Concrete simulated IoMT device implementations."""

from iomt_simulator.devices.ecg_monitor import ECGMonitor
from iomt_simulator.devices.infusion_pump import InfusionPump
from iomt_simulator.devices.support_assets import ClinicalWorkstation, NetworkGateway
from iomt_simulator.devices.ventilator import Ventilator

DEVICE_CLASSES = {
    "infusion_pump": InfusionPump,
    "ventilator": Ventilator,
    "ecg_monitor": ECGMonitor,
    "workstation": ClinicalWorkstation,
    "network_gateway": NetworkGateway,
}

__all__ = [
    "DEVICE_CLASSES",
    "ClinicalWorkstation",
    "ECGMonitor",
    "InfusionPump",
    "NetworkGateway",
    "Ventilator",
]
