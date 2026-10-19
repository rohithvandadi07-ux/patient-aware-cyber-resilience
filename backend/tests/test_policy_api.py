from app.policy_engine.table import get_active_table


def test_policy_endpoint_reports_active_policy_and_hash(client):
    response = client.get("/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["policy_hash"] == get_active_table().policy_hash
    assert len(body["policy_hash"]) == 64
    ids = [r["id"] for r in body["rules"]]
    assert ids[0] == "patient_dependent_severe_action"
    assert "approval_high_impact" in ids
    assert body["safety_floor"]
