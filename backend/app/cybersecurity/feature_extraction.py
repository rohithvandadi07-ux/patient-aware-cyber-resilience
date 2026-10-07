"""Window-based feature extraction: simulator events -> the model's feature vector.

Honesty note (read this before changing `FEATURE_COLUMNS` mappings below): the
baseline models in `training.py` are trained on `synthetic_data.py`'s columns,
which are themselves a labeled stand-in for CICIoMT2024's flow-level features
(packet/byte counts, inter-arrival times, TCP flag counts -- see that module's
docstring). The IoMT simulator (`app/iomt_simulator/`) does **not** capture raw
packets or TCP flags; it only emits `NetworkEvent` (one structured record per
scripted event, with a free-form `event_type`/`source`/`payload`) and
`TelemetryReading` (device vitals). There is therefore no real packet-level
measurement behind a feature like `syn_flag_count` for this simulator, the way
there would be for a real CICIoMT2024 flow capture.

Architecture spec Section 3's Risk 6 resolution requires feeding the simulator's
live event stream into "the same trained model" used for offline evaluation
(Risk 6: "the simulator's own network-event generator ... feeds the same
trained model to produce live detections"). To honor that without fabricating
packet-level measurements, this module computes a *documented proxy mapping*:
for each feature column, it derives the closest honestly-measurable statistic
from a window of the simulator's own events, and says so per-feature below.
Nothing here claims to be a real flow capture. If the simulator is later
extended to emit real per-packet statistics, this mapping should be replaced
with a direct computation and this module's docstring updated to say so.

Window: a fixed-size trailing window of `NetworkEvent`s for one device, plus
that device's most recent `TelemetryReading` (for telemetry-derived features).
Every value returned is traceable to a specific set of input events -- this is
also what `evidence_ref` on the resulting `DetectionEvent` points back to.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from app.cybersecurity.synthetic_data import FEATURE_COLUMNS
from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading

# Per-feature provenance, for anyone auditing what a score actually measures.
# "direct" = a real count/statistic computed from the window's events.
# "proxy"  = the closest honestly-available substitute for a flow-level
#            quantity the simulator does not itself model (no raw packets).
FEATURE_PROVENANCE: dict[str, str] = {
    "flow_duration": "direct -- window duration in seconds",
    "total_fwd_packets": "proxy -- count of events in the window (simulator has no packet counter)",
    "total_bwd_packets": "proxy -- fixed at 0.0; the simulator does not model response-direction traffic",
    "total_fwd_bytes": "proxy -- total character length of event payload values, summed over the window",
    "total_bwd_bytes": "proxy -- fixed at 0.0; no response-direction traffic is modeled",
    "packet_rate": "direct -- event count / window duration",
    "byte_rate": "direct -- total_fwd_bytes / window duration",
    "fwd_iat_mean": "direct -- mean seconds between consecutive events in the window",
    "bwd_iat_mean": "proxy -- fixed at 0.0; no response-direction traffic is modeled",
    "syn_flag_count": "proxy -- count of events whose event_type contains 'connect' or 'syn'",
    "ack_flag_count": "proxy -- count of events whose event_type contains 'command' or 'ack'",
    "rst_flag_count": "proxy -- count of events whose event_type contains 'fail' or 'reset'",
    "protocol_tcp": "proxy -- 1.0 unless payload declares a protocol, from NetworkEvent.payload['protocol']",
    "protocol_udp": "proxy -- from NetworkEvent.payload['protocol'] when present, else 0.0",
    "protocol_mqtt": "proxy -- 1.0 if any event_type/source/payload mentions 'mqtt', else 0.0",
}

assert set(FEATURE_PROVENANCE) == set(FEATURE_COLUMNS), (
    "FEATURE_PROVENANCE must document exactly the columns the model was trained on"
)


@dataclass
class FeatureWindow:
    """The raw inputs behind one extracted feature vector -- kept alongside the
    vector so a `DetectionEvent.evidence_ref` can point at something concrete
    and so tests can assert the mapping against known inputs."""

    device_id: str
    window_start: datetime
    window_end: datetime
    events: list[NetworkEvent]


def _duration_seconds(window: FeatureWindow) -> float:
    delta = (window.window_end - window.window_start).total_seconds()
    # A zero- or negative-length window (e.g. a single-instant snapshot) would
    # make rate features divide by zero; floor it at a small positive value
    # rather than special-casing every rate feature below.
    return max(delta, 1e-6)


def _mean_inter_arrival_seconds(events: list[NetworkEvent]) -> float:
    if len(events) < 2:
        return 0.0
    ordered = sorted(e.timestamp for e in events)
    deltas = [(b - a).total_seconds() for a, b in zip(ordered[:-1], ordered[1:], strict=True)]
    return sum(deltas) / len(deltas)


def _payload_byte_estimate(events: list[NetworkEvent]) -> float:
    total = 0
    for event in events:
        total += sum(len(key) + len(value) for key, value in event.payload.items())
    return float(total)


def _count_matching_event_type(events: list[NetworkEvent], needles: tuple[str, ...]) -> float:
    return float(sum(1 for e in events if any(n in e.event_type.lower() for n in needles)))


def _protocol_flags(events: list[NetworkEvent]) -> tuple[float, float, float]:
    declared = Counter(e.payload.get("protocol", "").lower() for e in events if e.payload.get("protocol"))
    mentions_mqtt = any(
        "mqtt" in e.event_type.lower() or "mqtt" in e.source.lower() or "mqtt" in str(e.payload).lower()
        for e in events
    )
    if mentions_mqtt:
        return (0.0, 0.0, 1.0)
    if declared:
        most_common_protocol = declared.most_common(1)[0][0]
        if most_common_protocol == "udp":
            return (0.0, 1.0, 0.0)
        if most_common_protocol == "mqtt":
            return (0.0, 0.0, 1.0)
    # Default: treat undeclared traffic as TCP, consistent with
    # `synthetic_data._PROTOCOL_BY_CLASS`'s default for benign/DoS/recon/spoofing.
    return (1.0, 0.0, 0.0)


def extract_features(window: FeatureWindow) -> dict[str, float]:
    """Compute the model's feature vector from one device's event window.

    Returns a dict keyed exactly by `FEATURE_COLUMNS` -- see module docstring
    and `FEATURE_PROVENANCE` for what each value really measures. An empty
    window (no events) yields an all-zero/minimal vector rather than raising,
    since "no activity this tick" is itself meaningful to the model.
    """
    events = window.events
    duration = _duration_seconds(window)
    event_count = float(len(events))
    fwd_bytes = _payload_byte_estimate(events)
    protocol_tcp, protocol_udp, protocol_mqtt = _protocol_flags(events)

    return {
        "flow_duration": duration,
        "total_fwd_packets": event_count,
        "total_bwd_packets": 0.0,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": 0.0,
        "packet_rate": event_count / duration,
        "byte_rate": fwd_bytes / duration,
        "fwd_iat_mean": _mean_inter_arrival_seconds(events),
        "bwd_iat_mean": 0.0,
        "syn_flag_count": _count_matching_event_type(events, ("connect", "syn")),
        "ack_flag_count": _count_matching_event_type(events, ("command", "ack")),
        "rst_flag_count": _count_matching_event_type(events, ("fail", "reset")),
        "protocol_tcp": protocol_tcp,
        "protocol_udp": protocol_udp,
        "protocol_mqtt": protocol_mqtt,
    }


def latest_telemetry_variance(readings: list[TelemetryReading], field_name: str) -> float | None:
    """Optional helper for future use: variance of one telemetry field across a
    window. Not currently wired into `extract_features` (the trained model's
    feature set has no telemetry-derived column), kept here because Section 12's
    dual-risk engine will want device-side signal distinct from network-side
    signal, and this is the natural place that logic will live.
    """
    values = [r.readings[field_name] for r in readings if field_name in r.readings]
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)
