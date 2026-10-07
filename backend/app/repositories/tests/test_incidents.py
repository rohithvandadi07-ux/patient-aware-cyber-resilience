import pytest

from app.repositories.incidents import IncidentNotFoundError, IncidentRepository
from app.schemas.enums import IncidentStatus


def test_create_returns_incident_with_detected_status():
    repo = IncidentRepository()
    incident = repo.create("incident-1", device_id="ventilator-01")
    assert incident.incident_id == "incident-1"
    assert incident.device_id == "ventilator-01"
    assert incident.status == IncidentStatus.DETECTED
    assert incident.chain_tx_id is None


def test_create_duplicate_incident_id_raises():
    repo = IncidentRepository()
    repo.create("incident-1", device_id="ventilator-01")
    with pytest.raises(ValueError, match="already exists"):
        repo.create("incident-1", device_id="ventilator-01")


def test_get_unknown_incident_raises_not_found():
    repo = IncidentRepository()
    with pytest.raises(IncidentNotFoundError):
        repo.get("does-not-exist")


def test_update_status_changes_status_and_updated_at():
    repo = IncidentRepository()
    created = repo.create("incident-1", device_id="ventilator-01")
    updated = repo.update_status("incident-1", IncidentStatus.INVESTIGATING)
    assert updated.status == IncidentStatus.INVESTIGATING
    assert updated.updated_at >= created.updated_at
    # The repository's own record reflects the update, not just the return value.
    assert repo.get("incident-1").status == IncidentStatus.INVESTIGATING


def test_list_for_device_returns_only_matching_incidents():
    repo = IncidentRepository()
    repo.create("incident-1", device_id="ventilator-01")
    repo.create("incident-2", device_id="infusion-pump-01")
    repo.create("incident-3", device_id="ventilator-01")
    results = repo.list_for_device("ventilator-01")
    assert {i.incident_id for i in results} == {"incident-1", "incident-3"}


def test_list_all_returns_every_incident():
    repo = IncidentRepository()
    repo.create("incident-1", device_id="ventilator-01")
    repo.create("incident-2", device_id="infusion-pump-01")
    assert len(repo.list_all()) == 2
