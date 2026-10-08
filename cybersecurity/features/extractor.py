"""Windowed feature extraction from the normalised event stream.

Converts the simulator's (or any adapter's) :class:`NormalisedEvent` stream
into canonical feature rows suitable for detection.

Design decisions that matter for research validity:

* **Windowing is per (device, window) rather than per event.** Several of
  the threat classes are only visible in aggregate - a port scan is not one
  packet, it is many packets to many ports - so a per-event classifier
  structurally cannot detect them.
* **Telemetry residuals, not raw vitals.** Feeding raw SpO2 to a classifier
  teaches it "low SpO2 means attack", which is a clinical-state detector, not
  an attack detector, and collapses on a genuinely sick patient. Instead we
  feed the *residual* against a short-run forecast and the variance ratio,
  which is what actually distinguishes spoofing (too smooth, wrong variance)
  from real physiology.
* **Nothing identifying.** No device id, IP, MAC or timestamp reaches the
  feature matrix; see ``schema.FORBIDDEN_FEATURES``.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from backend.app.domain.enums import AttackType, EventKind
from backend.app.domain.models import NormalisedEvent
from cybersecurity.schema import FEATURE_NAMES

#: Ports that legitimately carry IoMT service traffic in our environment.
IOMT_SERVICE_PORTS = {1883, 8883, 2575, 11073, 104, 4242}

#: Telemetry channels used for residual modelling, per device type. These are
#: the *reported* channels only; the simulator's truth channels are excluded
#: by FORBIDDEN_FEATURES and never referenced here.
RESIDUAL_CHANNELS: dict[str, tuple[str, ...]] = {
    "ventilator": ("spo2_pct", "respiratory_rate", "tidal_volume_ml", "etco2_mmhg"),
    "infusion_pump": ("actual_rate_ml_h", "occlusion_pressure_mmhg"),
    "ecg_monitor": ("heart_rate_bpm", "spo2_pct", "systolic_mmhg", "respiration_rpm"),
    "workstation": ("cpu_pct", "disk_write_mb_s"),
    "network_gateway": ("packets_per_second", "throughput_mbps"),
}


@dataclass
class _Baseline:
    """Rolling baseline for one telemetry channel of one device."""

    values: deque[float] = field(default_factory=lambda: deque(maxlen=60))

    def update(self, v: float) -> None:
        self.values.append(v)

    @property
    def ready(self) -> bool:
        return len(self.values) >= 10

    def mean(self) -> float:
        return statistics.fmean(self.values) if self.values else 0.0

    def stdev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        return statistics.pstdev(self.values)

    def forecast(self) -> float:
        """Short-run forecast: mean of the most recent third of the window."""
        if not self.values:
            return 0.0
        k = max(3, len(self.values) // 3)
        recent = list(self.values)[-k:]
        return statistics.fmean(recent)


@dataclass
class FeatureWindow:
    """One extracted feature row with its provenance and label."""

    device_id: str
    window_start: datetime
    window_end: datetime
    features: dict[str, float]
    event_ids: list[str] = field(default_factory=list)
    # Evaluation-only fields. Never passed to a model at inference time.
    y_binary: int = 0
    y_attack_type: str = AttackType.NONE.value
    scenario_id: str | None = None

    def feature_vector(self, order: tuple[str, ...] = FEATURE_NAMES) -> list[float]:
        return [self.features.get(name, 0.0) for name in order]

    def available_features(self) -> list[str]:
        return sorted(self.features)


class WindowedFeatureExtractor:
    """Aggregates events into per-device windows of canonical features.

    Stateful across windows: telemetry baselines persist so that residuals
    are meaningful. Call :meth:`reset` between independent runs.
    """

    def __init__(self, window_seconds: float = 5.0, baseline_window: int = 60) -> None:
        self.window_seconds = window_seconds
        self.baseline_window = baseline_window
        self._baselines: dict[tuple[str, str], _Baseline] = defaultdict(
            lambda: _Baseline(deque(maxlen=baseline_window))
        )

    def reset(self) -> None:
        self._baselines.clear()

    # -- public API --------------------------------------------------------
    def extract(self, events: list[NormalisedEvent]) -> list[FeatureWindow]:
        """Extract all complete windows from a batch of events."""
        if not events:
            return []
        buckets: dict[tuple[str, int], list[NormalisedEvent]] = defaultdict(list)
        t0 = min(e.timestamp for e in events)
        for ev in events:
            if ev.device_id is None:
                continue
            idx = int((ev.timestamp - t0).total_seconds() // self.window_seconds)
            buckets[(ev.device_id, idx)].append(ev)

        windows: list[FeatureWindow] = []
        for device_id, idx in sorted(buckets, key=lambda k: (k[1], k[0])):
            group = buckets[(device_id, idx)]
            start = t0 + timedelta(seconds=idx * self.window_seconds)
            windows.append(
                self._build_window(
                    device_id=device_id,
                    events=group,
                    start=start,
                    end=start + timedelta(seconds=self.window_seconds),
                )
            )
        return windows

    # -- internals ---------------------------------------------------------
    def _build_window(
        self,
        device_id: str,
        events: list[NormalisedEvent],
        start: datetime,
        end: datetime,
    ) -> FeatureWindow:
        f: dict[str, float] = {}

        flows = [e for e in events if e.kind is EventKind.NETWORK_FLOW]
        telemetry = [e for e in events if e.kind is EventKind.TELEMETRY]
        commands = [e for e in events if e.kind is EventKind.DEVICE_COMMAND]
        auth = [e for e in events if e.kind is EventKind.AUTH]

        self._flow_features(flows, f)
        self._telemetry_features(device_id, telemetry, f)
        self._command_features(commands, f)
        self._auth_features(auth, f)

        # Label: an attack label on ANY event in the window labels the window.
        attack_events = [e for e in events if e.ground_truth_is_attack]
        y_binary = int(bool(attack_events))
        y_type = (
            attack_events[0].ground_truth_attack.value
            if attack_events and attack_events[0].ground_truth_attack
            else AttackType.NONE.value
        )

        return FeatureWindow(
            device_id=device_id,
            window_start=start,
            window_end=end,
            features={k: float(v) for k, v in f.items() if math.isfinite(v)},
            event_ids=[e.event_id for e in events],
            y_binary=y_binary,
            y_attack_type=y_type,
            scenario_id=events[0].scenario_id if events else None,
        )

    def _flow_features(self, flows: list[NormalisedEvent], f: dict[str, float]) -> None:
        if not flows:
            return
        pps = [e.measurements.get("packets_per_second", 0.0) for e in flows]
        bps = [e.measurements.get("bytes_per_second", 0.0) for e in flows]
        pkt_b = [e.measurements.get("mean_packet_bytes", 0.0) for e in flows]
        iats = [e.measurements.get("mean_iat_ms", 0.0) for e in flows]

        # VOLUME AGGREGATION AND THE FLOW-COUNT ARTIFACT
        #
        # Summing per-flow volumes across a window makes the NUMBER of flow
        # records an implicit feature. Measured on `stealth_low_rate_dos`,
        # a 1.5%-intensity attack whose own packet rate (414 pps mean) was
        # LOWER than the benign baseline (622 pps mean) still reached
        # single-feature AUC 0.985 on summed `packets`, purely because it
        # reliably added +1.09 flow records per tick. The classifier was
        # counting records, not reading traffic.
        #
        # Volume is therefore aggregated as the window MAXIMUM (the busiest
        # single flow) and the MEDIAN (the typical flow), neither of which
        # grows mechanically with the record count. A flood still shows a
        # large maximum; a quiet attack that merely adds a record does not
        # move either statistic. See docs/detection-validity.md.
        f["packets_per_second"] = max(pps) if pps else 0.0
        f["bytes_per_second"] = max(bps) if bps else 0.0
        f["packets"] = (
            statistics.median([e.measurements.get("packets", 0.0) for e in flows]) if flows else 0.0
        )
        f["bytes"] = (
            statistics.median([e.measurements.get("bytes", 0.0) for e in flows]) if flows else 0.0
        )
        f["mean_packet_bytes"] = statistics.fmean(pkt_b) if pkt_b else 0.0
        # Mean, not sum: a sum is proportional to the flow count.
        f["flow_duration_s"] = (
            statistics.fmean([e.measurements.get("flow_duration_s", 0.0) for e in flows])
            if flows
            else 0.0
        )
        f["mean_iat_ms"] = statistics.fmean(iats) if iats else 0.0
        f["iat_std_ms"] = statistics.pstdev(iats) if len(iats) > 1 else 0.0

        f["syn_ratio"] = max((e.measurements.get("syn_ratio", 0.0) for e in flows), default=0.0)
        f["distinct_dst_ports"] = max(
            (e.measurements.get("distinct_dst_ports", 0.0) for e in flows), default=0.0
        )
        # Expressed as a ratio so it measures destination SPREAD rather than
        # growing mechanically with the number of flow records.
        hosts = {e.destination_ip for e in flows if e.destination_ip}
        f["distinct_dst_hosts"] = len(hosts) / max(1, len(flows))
        f["arp_table_changes"] = max(
            (e.measurements.get("arp_table_changes", 0.0) for e in flows), default=0.0
        )
        f["duplicate_mac_observed"] = max(
            (e.measurements.get("duplicate_mac_observed", 0.0) for e in flows), default=0.0
        )
        f["ttl_variance"] = max(
            (e.measurements.get("ttl_variance", 0.0) for e in flows), default=0.0
        )
        f["rtt_ms"] = max((e.measurements.get("rtt_ms", 0.0) for e in flows), default=0.0)
        f["tls_downgrade"] = max(
            (e.measurements.get("tls_downgrade", 0.0) for e in flows), default=0.0
        )

        protocols = [(e.protocol or "").lower() for e in flows]
        f["is_tcp"] = float(any(p == "tcp" for p in protocols))
        f["is_udp"] = float(any(p == "udp" for p in protocols))
        f["is_arp"] = float(any(p == "arp" for p in protocols))
        f["is_icmp"] = float(any(p == "icmp" for p in protocols))

        dports = [e.destination_port for e in flows if e.destination_port is not None]
        f["dst_port_is_wellknown"] = float(any(p < 1024 for p in dports))
        f["dst_port_is_iomt_service"] = float(any(p in IOMT_SERVICE_PORTS for p in dports))

    def _telemetry_features(
        self, device_id: str, telemetry: list[NormalisedEvent], f: dict[str, float]
    ) -> None:
        if not telemetry:
            return
        device_type = telemetry[0].attributes.get("device_type", "")
        channels = RESIDUAL_CHANNELS.get(device_type, ())

        residuals: list[float] = []
        variance_ratios: list[float] = []

        for channel in channels:
            observed = [e.measurements[channel] for e in telemetry if channel in e.measurements]
            if not observed:
                continue
            key = (device_id, channel)
            baseline = self._baselines[key]

            if baseline.ready:
                forecast = baseline.forecast()
                expected_sd = baseline.stdev()
                current = statistics.fmean(observed)
                # Standardised residual, robust to a flat baseline.
                denom = expected_sd if expected_sd > 1e-6 else max(abs(forecast) * 0.01, 1e-3)
                residuals.append(abs(current - forecast) / denom)

                # Variance ratio: spoofed telemetry is characteristically
                # *too smooth*, so a ratio well below 1 is as suspicious as
                # one well above.
                observed_sd = statistics.pstdev(observed) if len(observed) > 1 else 0.0
                if expected_sd > 1e-6:
                    variance_ratios.append(observed_sd / expected_sd)

            for v in observed:
                baseline.update(v)

        if residuals:
            f["telemetry_residual"] = max(residuals)
        if variance_ratios:
            f["telemetry_variance_ratio"] = statistics.fmean(variance_ratios)

        f["alarm_active"] = float(any(e.attributes.get("alarm") == "true" for e in telemetry))
        f["missed_samples"] = max(
            (e.measurements.get("missed_samples", 0.0) for e in telemetry), default=0.0
        )

        # Host-behaviour channels, when the asset reports them.
        for key in ("cpu_pct", "disk_write_mb_s", "process_count", "encrypted_file_ops"):
            vals = [e.measurements[key] for e in telemetry if key in e.measurements]
            if vals:
                f[key] = max(vals)

    def _command_features(self, commands: list[NormalisedEvent], f: dict[str, float]) -> None:
        if not commands:
            return
        f["authenticated_session"] = min(
            (e.measurements.get("authenticated_session", 1.0) for e in commands), default=1.0
        )
        f["exceeds_safe_limit"] = max(
            (e.measurements.get("exceeds_safe_limit", 0.0) for e in commands), default=0.0
        )
        f["reduces_support"] = max(
            (e.measurements.get("reduces_support", 0.0) for e in commands), default=0.0
        )
        deltas = [abs(e.measurements.get("delta_rate_ml_h", 0.0)) for e in commands] + [
            abs(e.measurements.get("requested_rr", 0.0) - 14.0)
            for e in commands
            if "requested_rr" in e.measurements
        ]
        if deltas:
            f["delta_setpoint_abs"] = max(deltas)
        f["source_offsegment"] = float(
            any(
                e.attributes.get("source_segment", "vlan-clinical") not in {"vlan-clinical", ""}
                for e in commands
            )
        )

    def _auth_features(self, auth: list[NormalisedEvent], f: dict[str, float]) -> None:
        if not auth:
            return
        f["failed_attempts"] = max(
            (e.measurements.get("failed_attempts", 0.0) for e in auth), default=0.0
        )
        succeeded = any(e.measurements.get("succeeded", 0.0) > 0 for e in auth)
        f["auth_succeeded"] = float(succeeded)
        # Success following many failures is the brute-force success signature.
        f["auth_after_failures"] = float(succeeded and f.get("failed_attempts", 0.0) >= 10.0)


__all__ = [
    "IOMT_SERVICE_PORTS",
    "RESIDUAL_CHANNELS",
    "FeatureWindow",
    "WindowedFeatureExtractor",
]
