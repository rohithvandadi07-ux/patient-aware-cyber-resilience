"""`/detections` API tests.

Exercises the route wiring (status codes, response shape, dependency
override) rather than re-testing detection scoring logic itself -- that is
`app/cybersecurity/tests/test_detection_service.py`'s job. Uses a real,
quickly-trained model fixture via `app.dependency_overrides`, the same
pattern FastAPI documents for substituting a test double for a Depends().
"""

import pytest
from fastapi.testclient import TestClient

from app.api.detections import get_detection_service
from app.cybersecurity.detection_service import DetectionService, load_model
from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import save_artifacts, train_baselines
from app.main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def trained_service(tmp_path_factory):
    output_dir = tmp_path_factory.mktemp("detections_api_models")
    df = generate_synthetic_dataset(seed=11)
    results = train_baselines(df, seed=11)
    save_artifacts(results, output_dir, data_source="synthetic (API test fixture)", seed=11)
    model = load_model(output_dir / "random_forest.joblib")
    return DetectionService(model, confidence_threshold=0.0)


def test_run_scenario_without_model_returns_503():
    # No override installed -- the real get_detection_service looks for
    # experiments/models/random_forest.joblib, which does not exist in this
    # test environment (gitignored, never committed).
    assert get_detection_service not in app.dependency_overrides
    response = client.post("/detections/run-scenario")
    assert response.status_code == 503
    assert "Train one first" in response.json()["detail"]


def test_run_scenario_with_model_returns_detection_list(trained_service):
    app.dependency_overrides[get_detection_service] = lambda: trained_service
    try:
        response = client.post("/detections/run-scenario")
    finally:
        app.dependency_overrides.pop(get_detection_service, None)

    assert response.status_code == 200
    detections = response.json()
    assert isinstance(detections, list)
    for detection in detections:
        assert detection["device_id"] in {"infusion-pump-01", "ventilator-01", "ecg-monitor-01"}
        assert 0.0 <= detection["confidence"] <= 1.0
        assert detection["attack_type"] != "unknown"


def test_run_scenario_records_telemetry_events_and_incidents_with_provenance(trained_service):
    """Phase 9: the scenario's own telemetry/events land in the shared
    stores `/telemetry`/`/events` read from, and every DetectionEvent
    becomes a real, queryable Incident with a PENDING blockchain outbox
    entry -- not just a response body nothing else can see."""
    events_before = len(app.state.network_event_store.query())
    telemetry_before = len(app.state.telemetry_store.query())
    incidents_before = len(app.state.incident_repository.list_all())

    app.dependency_overrides[get_detection_service] = lambda: trained_service
    try:
        response = client.post("/detections/run-scenario")
    finally:
        app.dependency_overrides.pop(get_detection_service, None)

    assert response.status_code == 200
    detections = response.json()

    # The scenario always emits one attack-injection network event and ten
    # ticks of telemetry per device, regardless of whether anything crosses
    # the model's detection threshold.
    assert len(app.state.network_event_store.query()) == events_before + 1
    assert len(app.state.telemetry_store.query()) > telemetry_before

    incidents_after = app.state.incident_repository.list_all()
    assert len(incidents_after) == incidents_before + len(detections)

    for detection in detections:
        matching = [
            i for i in incidents_after if i.device_id == detection["device_id"] and i.status == "detected"
        ]
        assert matching, f"no Incident recorded for detection on {detection['device_id']}"
        outbox_entries = app.state.outbox_repository.list_for_incident(matching[-1].incident_id)
        assert any(e.record_type == "incident" and e.status == "pending" for e in outbox_entries)
