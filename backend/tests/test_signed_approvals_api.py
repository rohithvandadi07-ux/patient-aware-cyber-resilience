"""Signed approvals on /responses/executed. Own `create_app()` instance."""

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.approvals.signing import approval_message
from app.core.app_factory import create_app
from app.core.config import Settings, get_settings

app = create_app()
client = TestClient(app)


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.b64encode(public).decode()


ALICE, ALICE_PUB = keypair()
MALLORY, _ = keypair()


@pytest.fixture
def signing_required():
    app.dependency_overrides[get_settings] = lambda: Settings(
        approver_public_keys={"dr-alice": ALICE_PUB}, require_signed_approvals=True
    )
    yield
    app.dependency_overrides.pop(get_settings, None)


@pytest.fixture
def signing_optional():
    app.dependency_overrides[get_settings] = lambda: Settings(approver_public_keys={"dr-alice": ALICE_PUB})
    yield
    app.dependency_overrides.pop(get_settings, None)


def pending():
    """An incident with a pending decision that needs human approval (rotate_credentials is repeatable)."""
    iid = f"SIGN-{uuid4().hex[:8]}"
    r = client.post("/incidents", json={
        "incident_id": iid, "device_id": "ventilator-01", "attack_type": "mqtt_based",
        "evidence_ref": f"ev-{iid}", "timestamp": "2026-10-19T00:00:00+00:00"})
    assert r.status_code == 201
    action = "rotate_credentials"
    r = client.post("/responses/proposed", json={
        "risk_score": {"incident_id": iid, "cyber_risk": 0.8, "clinical_risk": 0.5,
                       "response_impact": {action: "high"}, "explanation": "test"},
        "proposed_response": {"incident_id": iid,
                              "candidate_actions": [{"action_category": action, "description": "d"}],
                              "security_benefit": {action: 0.7}, "clinical_impact": {action: "high"},
                              "recommended_action": action, "rationale": "r"},
        "context": {"incident_id": iid, "device_criticality": "high", "patient_dependency": True,
                    "clinical_impact_level": "high", "safety_constraints": []},
    })
    assert r.status_code == 201
    return iid, r.json()


def approval(iid, decision_json, key, identity="dr-alice", decision="approved", ts=None,
             sign_incident=None, sign_decision=None):
    ts = ts or datetime.now(UTC)
    message = approval_message(sign_incident or iid, decision_json["chosen_action"],
                               decision_json["policy_rule_id"], sign_decision or decision, ts)
    return {"incident_id": iid, "approver_identity": identity, "decision": decision,
            "timestamp": ts.isoformat(), "signature": base64.b64encode(key.sign(message)).decode()}


def execute(iid, approval_body):
    return client.post("/responses/executed", json={"incident_id": iid, "approval": approval_body})


def still_pending(iid):
    return client.get(f"/responses/proposed/{iid}").status_code == 200


def test_unsigned_approval_still_works_when_signing_is_not_required():
    iid, _ = pending()
    r = execute(iid, {"incident_id": iid, "approver_identity": "anyone", "decision": "approved",
                      "timestamp": datetime.now(UTC).isoformat()})
    assert r.status_code == 201 and r.json()["executed_by"] == "anyone"


def test_valid_signature_executes_under_the_verified_identity(signing_required):
    iid, decision = pending()
    r = execute(iid, approval(iid, decision, ALICE))
    assert r.status_code == 201 and r.json()["executed_by"] == "dr-alice"


def test_unsigned_approval_is_refused_when_required(signing_required):
    iid, _ = pending()
    r = execute(iid, {"incident_id": iid, "approver_identity": "dr-alice", "decision": "approved",
                      "timestamp": datetime.now(UTC).isoformat()})
    assert r.status_code == 403 and still_pending(iid)


def test_signature_from_the_wrong_key_is_refused(signing_required):
    iid, decision = pending()
    assert execute(iid, approval(iid, decision, MALLORY)).status_code == 403
    assert still_pending(iid)


def test_unregistered_identity_is_refused_with_the_same_answer(signing_required):
    iid, decision = pending()
    forged = execute(iid, approval(iid, decision, MALLORY, identity="dr-nobody"))
    wrong_key = execute(iid, approval(iid, decision, MALLORY))
    assert forged.status_code == wrong_key.status_code == 403
    assert forged.json() == wrong_key.json()


def test_changing_the_decision_after_signing_is_refused(signing_required):
    iid, decision = pending()
    r = execute(iid, approval(iid, decision, ALICE, decision="rejected", sign_decision="approved"))
    assert r.status_code == 403 and still_pending(iid)


def test_signature_for_another_incident_cannot_be_replayed(signing_required):
    iid, decision = pending()
    r = execute(iid, approval(iid, decision, ALICE, sign_incident="SOME-OTHER-INCIDENT"))
    assert r.status_code == 403 and still_pending(iid)


def test_stale_signed_approval_is_refused(signing_required):
    iid, decision = pending()
    old = datetime.now(UTC) - timedelta(minutes=30)
    assert execute(iid, approval(iid, decision, ALICE, ts=old)).status_code == 403


def test_a_present_but_invalid_signature_is_refused_even_when_not_required(signing_optional):
    iid, decision = pending()
    assert execute(iid, approval(iid, decision, MALLORY)).status_code == 403
    assert execute(iid, approval(iid, decision, ALICE)).status_code == 201


def test_public_key_settings_parse_and_validate():
    s = Settings(approver_public_keys=f"dr-alice={ALICE_PUB}, dr-bob={ALICE_PUB}")
    assert set(s.approver_public_keys) == {"dr-alice", "dr-bob"}
    assert Settings(approver_public_keys="").approver_public_keys == {}
    with pytest.raises(ValidationError):
        Settings(approver_public_keys="dr-alice=not-base64!!")
    with pytest.raises(ValidationError):
        Settings(approver_public_keys="dr-alice=" + base64.b64encode(b"short").decode())
    with pytest.raises(ValidationError):
        Settings(approver_public_keys="no-equals-sign")


def test_auto_approve_cannot_sidestep_required_signatures(signing_required):
    iid, _ = pending()
    r = client.post(f"/incidents/{iid}/investigate", json={"auto_approve": True})
    assert r.status_code == 403
    assert "signed approvals" in r.json()["detail"]
    assert still_pending(iid)
