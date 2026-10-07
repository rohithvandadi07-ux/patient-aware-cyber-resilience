# telemetry

L2 of the architecture. Collects device telemetry, network events, and security
events emitted by the simulator and writes them to the time-series store
(TimescaleDB hypertables), tagged by device ID and timestamp.

Status: not started. Phase 2 work (built alongside the simulator it collects from).
