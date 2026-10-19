from fastapi.testclient import TestClient

from app.core.app_factory import create_app
from app.core.auth import Principal, get_current_principal
from app.core.config import Settings


def _make(demo: bool):
    app = create_app(Settings(demo_mode=demo))
    return app, TestClient(app)


def test_status_reports_disabled_by_default():
    _, client = _make(False)
    assert client.get("/demo/status").json() == {"enabled": False}


def test_status_reports_enabled():
    _, client = _make(True)
    assert client.get("/demo/status").json() == {"enabled": True}


def test_reset_is_404_when_demo_mode_off_and_changes_nothing():
    app, client = _make(False)
    app.state.incident_repository.create("KEEP-1", "ventilator-01")
    assert client.post("/demo/reset").status_code == 404
    assert len(app.state.incident_repository.list_all()) == 1


def test_reset_clears_state_and_keeps_registry_identity():
    app, client = _make(True)
    registry_before = app.state.device_registry
    patients_before = app.state.patient_registry
    n_devices = len(registry_before)
    app.state.incident_repository.create("DEMO-1", "ventilator-01")
    app.state.incident_repository.create("DEMO-2", "ventilator-01")
    patients_before.advance(30)
    assert patients_before.simulated_minute == 30

    resp = client.post("/demo/reset")
    assert resp.status_code == 200
    assert resp.json()["incidents_removed"] == 2

    assert app.state.incident_repository.list_all() == []
    assert app.state.device_registry is registry_before
    assert app.state.patient_registry is patients_before
    assert len(app.state.device_registry) == n_devices
    assert app.state.patient_registry.simulated_minute == 0


def test_reset_requires_approver_role():
    app, client = _make(True)
    app.dependency_overrides[get_current_principal] = lambda: Principal(identity="v", role="viewer")
    assert client.post("/demo/reset").status_code == 403
    app.dependency_overrides[get_current_principal] = lambda: Principal(identity="a", role="approver")
    assert client.post("/demo/reset").status_code == 200
