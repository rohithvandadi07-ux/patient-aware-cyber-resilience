from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_list_devices_returns_default_fleet():
    response = client.get("/devices")
    assert response.status_code == 200
    devices = response.json()
    assert len(devices) == 3
    device_ids = {d["device_id"] for d in devices}
    assert device_ids == {"infusion-pump-01", "ventilator-01", "ecg-monitor-01"}


def test_get_device_returns_expected_clinical_attributes():
    response = client.get("/devices/ventilator-01")
    assert response.status_code == 200
    body = response.json()
    assert body["device_type"] == "ventilator"
    assert body["criticality"] == "high"
    assert body["patient_dependency"] is True


def test_get_unknown_device_returns_404():
    response = client.get("/devices/does-not-exist")
    assert response.status_code == 404
