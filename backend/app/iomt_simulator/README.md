# iomt_simulator

L1 of the architecture. Simulated smart-hospital IoMT devices (infusion pump,
ventilator, ECG/patient monitor) as state machines with clinical attributes
(criticality, patient dependency, synthetic patient ID) and a telemetry generator.
Includes the deterministic `ScenarioRunner` used to inject controlled, reproducible
attack scenarios for testing and experiments.

Status: not started. Phase 2 work.
