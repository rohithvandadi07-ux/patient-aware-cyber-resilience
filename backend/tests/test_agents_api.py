from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def test_list_agent_traces_is_empty_before_any_agent_has_run():
    response = client.get("/agents")
    assert response.status_code == 200
    assert response.json() == []


def test_list_agent_traces_for_unknown_incident_is_empty_not_fabricated():
    response = client.get("/agents/does-not-exist")
    assert response.status_code == 200
    assert response.json() == []


def test_recorded_traces_are_listed_and_filterable():
    recorder = app.state.agent_trace_recorder
    recorder.record_success(
        incident_id="INC-1",
        agent_name="investigation",
        input_payload={"incident_id": "INC-1", "device_id": "ventilator-01"},
        output_payload={"evidence": ["log-line-1"]},
    )
    recorder.record_failure(
        incident_id="INC-1",
        agent_name="threat_reasoning",
        input_payload={"incident_id": "INC-1"},
        error="schema validation failed after retry",
    )
    recorder.record_success(
        incident_id="INC-2",
        agent_name="investigation",
        input_payload={"incident_id": "INC-2", "device_id": "ecg-monitor-01"},
        output_payload={"evidence": []},
    )

    all_traces = client.get("/agents").json()
    assert len(all_traces) == 3

    inc1_traces = client.get("/agents/INC-1").json()
    assert {t["agent_name"] for t in inc1_traces} == {"investigation", "threat_reasoning"}

    failed = [t for t in inc1_traces if not t["succeeded"]]
    assert len(failed) == 1
    assert failed[0]["error"] == "schema validation failed after retry"

    filtered_by_agent = client.get("/agents", params={"agent_name": "investigation"}).json()
    assert len(filtered_by_agent) == 2
    assert all(t["agent_name"] == "investigation" for t in filtered_by_agent)

    filtered_by_both = client.get(
        "/agents", params={"incident_id": "INC-1", "agent_name": "investigation"}
    ).json()
    assert len(filtered_by_both) == 1
    assert filtered_by_both[0]["incident_id"] == "INC-1"
