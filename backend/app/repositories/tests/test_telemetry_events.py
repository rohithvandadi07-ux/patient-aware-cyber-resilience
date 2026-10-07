from datetime import UTC, datetime

from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_network_event_store_query_filters_by_device():
    store = NetworkEventStore()
    store.record_many(
        [
            NetworkEvent(device_id="ventilator-01", timestamp=_NOW, event_type="a", source="x"),
            NetworkEvent(device_id="infusion-pump-01", timestamp=_NOW, event_type="b", source="y"),
        ]
    )
    results = store.query(device_id="ventilator-01")
    assert len(results) == 1
    assert results[0].event_type == "a"


def test_network_event_store_query_without_filter_returns_all():
    store = NetworkEventStore()
    store.record_many(
        [
            NetworkEvent(device_id="ventilator-01", timestamp=_NOW, event_type="a", source="x"),
            NetworkEvent(device_id="infusion-pump-01", timestamp=_NOW, event_type="b", source="y"),
        ]
    )
    assert len(store.query()) == 2


def test_network_event_store_clear_empties_store():
    store = NetworkEventStore()
    store.record_many([NetworkEvent(device_id="x", timestamp=_NOW, event_type="a", source="y")])
    store.clear()
    assert store.query() == []


def test_telemetry_store_query_filters_by_device():
    store = TelemetryStore()
    store.record_many(
        [
            TelemetryReading(
                device_id="ventilator-01", timestamp=_NOW, readings={"heart_rate_bpm": 72.0}
            ),
            TelemetryReading(
                device_id="infusion-pump-01", timestamp=_NOW, readings={"flow_rate_ml_per_hr": 100.0}
            ),
        ]
    )
    results = store.query(device_id="ventilator-01")
    assert len(results) == 1
    assert results[0].readings == {"heart_rate_bpm": 72.0}


def test_telemetry_store_returns_empty_list_for_unknown_device():
    store = TelemetryStore()
    assert store.query(device_id="does-not-exist") == []
