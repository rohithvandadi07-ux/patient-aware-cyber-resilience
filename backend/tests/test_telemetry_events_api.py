"""`/telemetry` and `/events` API tests.

Uses its own `create_app()` instance (not the shared `app.main.app`
singleton `test_devices_api.py`/`test_detections_api.py` import) so this
file's assertions about what's recorded are never affected by another test
file populating the same process-wide app's stores -- see
`app/core/app_factory.py`'s Phase 9 docstring for why these stores are
`app.state`, not module globals.
"""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.core.app_factory import create_app
from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading

app = create_app()
client = TestClient(app)


def test_list_telemetry_is_empty_before_anything_is_recorded():
    response = client.get("/telemetry")
    assert response.status_code == 200
    assert response.json() == []


def test_list_telemetry_returns_recorded_readings_and_filters_by_device():
    app.state.telemetry_store.record_many(
        [
            TelemetryReading(
                device_id="ventilator-01",
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                readings={"respiratory_rate_bpm": 14.0},
            ),
            TelemetryReading(
                device_id="ecg-monitor-01",
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                readings={"heart_rate_bpm": 72.0},
            ),
        ]
    )

    all_readings = client.get("/telemetry").json()
    assert len(all_readings) == 2

    filtered = client.get("/telemetry", params={"device_id": "ventilator-01"}).json()
    assert len(filtered) == 1
    assert filtered[0]["device_id"] == "ventilator-01"
    assert filtered[0]["readings"]["respiratory_rate_bpm"] == 14.0


def test_list_events_is_empty_before_anything_is_recorded():
    response = client.get("/events")
    assert response.status_code == 200
    assert response.json() == []


def test_list_events_returns_recorded_events_and_filters_by_device():
    app.state.network_event_store.record_many(
        [
            NetworkEvent(
                device_id="ventilator-01",
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                event_type="spoofed_command",
                source="scenario_runner",
                is_attack_injection=True,
            )
        ]
    )

    events = client.get("/events", params={"device_id": "ventilator-01"}).json()
    assert len(events) == 1
    assert events[0]["event_type"] == "spoofed_command"
    assert events[0]["is_attack_injection"] is True

    none_for_other_device = client.get("/events", params={"device_id": "infusion-pump-01"}).json()
    assert none_for_other_device == []
