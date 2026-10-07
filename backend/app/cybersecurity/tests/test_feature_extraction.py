from datetime import UTC, datetime, timedelta

from app.cybersecurity.feature_extraction import (
    FEATURE_PROVENANCE,
    FeatureWindow,
    extract_features,
)
from app.cybersecurity.synthetic_data import FEATURE_COLUMNS
from app.schemas.events import NetworkEvent

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _event(offset_seconds: float, event_type: str, source: str = "10.0.0.1", **payload: str) -> NetworkEvent:
    return NetworkEvent(
        device_id="ventilator-01",
        timestamp=_NOW + timedelta(seconds=offset_seconds),
        event_type=event_type,
        source=source,
        payload=payload,
        is_attack_injection=True,
    )


def _window(events: list[NetworkEvent], duration_seconds: float, device_id: str = "x") -> FeatureWindow:
    return FeatureWindow(
        device_id=device_id,
        window_start=_NOW,
        window_end=_NOW + timedelta(seconds=duration_seconds),
        events=events,
    )


def test_feature_provenance_documents_every_trained_column():
    # extract_features must return exactly the columns the model was trained
    # on (synthetic_data.FEATURE_COLUMNS) -- a mismatch here would silently
    # break prediction (wrong column order/set fed to the estimator).
    assert set(FEATURE_PROVENANCE) == set(FEATURE_COLUMNS)


def test_empty_window_returns_zeroed_counts_not_a_crash():
    features = extract_features(_window([], duration_seconds=5))
    assert set(features) == set(FEATURE_COLUMNS)
    assert features["total_fwd_packets"] == 0.0
    assert features["packet_rate"] == 0.0
    assert features["fwd_iat_mean"] == 0.0


def test_event_count_maps_to_total_fwd_packets():
    events = [_event(i * 0.1, "connection_attempt") for i in range(10)]
    features = extract_features(_window(events, duration_seconds=1))
    assert features["total_fwd_packets"] == 10.0


def test_packet_rate_is_event_count_over_duration():
    events = [_event(i * 0.1, "connection_attempt") for i in range(10)]
    features = extract_features(_window(events, duration_seconds=2))
    assert features["packet_rate"] == 5.0  # 10 events / 2 seconds


def test_syn_flag_count_matches_connect_and_syn_event_types():
    events = [
        _event(0, "connection_attempt_syn"),
        _event(1, "command_received"),
        _event(2, "connect"),
    ]
    features = extract_features(_window(events, duration_seconds=3))
    assert features["syn_flag_count"] == 2.0
    assert features["ack_flag_count"] == 1.0


def test_rst_flag_count_matches_fail_and_reset_event_types():
    events = [_event(0, "auth_failure"), _event(1, "connection_reset"), _event(2, "command_received")]
    features = extract_features(_window(events, duration_seconds=3))
    assert features["rst_flag_count"] == 2.0


def test_protocol_mqtt_detected_from_event_type():
    features = extract_features(_window([_event(0, "mqtt_connect_flood")], duration_seconds=1))
    assert features["protocol_mqtt"] == 1.0
    assert features["protocol_tcp"] == 0.0
    assert features["protocol_udp"] == 0.0


def test_protocol_declared_in_payload_is_respected():
    events = [_event(0, "connection_attempt", protocol="udp")]
    features = extract_features(_window(events, duration_seconds=1))
    assert features["protocol_udp"] == 1.0
    assert features["protocol_tcp"] == 0.0


def test_default_protocol_is_tcp_when_undeclared():
    features = extract_features(_window([_event(0, "command_received")], duration_seconds=1))
    assert features["protocol_tcp"] == 1.0


def test_fwd_iat_mean_is_average_gap_between_sorted_events():
    events = [_event(0, "a"), _event(2, "b"), _event(6, "c")]  # gaps: 2, 4 -> mean 3
    features = extract_features(_window(events, duration_seconds=10))
    assert features["fwd_iat_mean"] == 3.0


def test_backward_direction_features_are_always_zero():
    # The simulator does not model response-direction traffic at all --
    # these must stay fixed at 0.0 rather than silently drifting if the
    # extraction logic changes.
    features = extract_features(_window([_event(0, "command_received")], duration_seconds=1))
    assert features["total_bwd_packets"] == 0.0
    assert features["total_bwd_bytes"] == 0.0
    assert features["bwd_iat_mean"] == 0.0
