"""Real tests for the post-Phase-15 auth layer (`app/core/auth.py`).

Two app instances: one with `auth_enabled=False` (the default -- proves
nothing changed for the historical no-auth behavior) and one with
`auth_enabled=True` and real configured keys (proves the X-API-Key check,
the role hierarchy, and the fail-closed-with-no-keys case are all real,
not just described in a docstring).
"""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app
from app.core.config import Settings


def _settings(**overrides) -> Settings:
    return Settings(**overrides)


def test_auth_disabled_by_default_every_pre_existing_route_still_works_unauthenticated():
    app = create_app(_settings())
    client = TestClient(app)
    assert client.get("/devices").status_code == 200
    assert client.get("/incidents").status_code == 200


def test_health_is_exempt_even_when_auth_enabled():
    app = create_app(_settings(auth_enabled=True, api_keys={"k1": ("viewer", "alice")}))
    client = TestClient(app)
    assert client.get("/health").status_code == 200


def test_auth_enabled_with_no_keys_locks_out_every_non_health_route():
    """Fail closed: auth_enabled=True with an empty api_keys map must deny
    everything (401), never silently behave as if auth were off."""
    app = create_app(_settings(auth_enabled=True, api_keys={}))
    client = TestClient(app)
    assert client.get("/devices").status_code == 401
    assert client.get("/incidents").status_code == 401


def test_auth_enabled_missing_header_returns_401():
    app = create_app(_settings(auth_enabled=True, api_keys={"k1": ("viewer", "alice")}))
    client = TestClient(app)
    response = client.get("/devices")
    assert response.status_code == 401
    assert "X-API-Key" in response.json()["detail"]


def test_auth_enabled_wrong_key_returns_401():
    app = create_app(_settings(auth_enabled=True, api_keys={"k1": ("viewer", "alice")}))
    client = TestClient(app)
    response = client.get("/devices", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401


def test_auth_enabled_valid_viewer_key_can_read():
    app = create_app(_settings(auth_enabled=True, api_keys={"k1": ("viewer", "alice")}))
    client = TestClient(app)
    response = client.get("/devices", headers={"X-API-Key": "k1"})
    assert response.status_code == 200


def test_viewer_cannot_auto_approve_investigate_but_operator_can_investigate_without_it():
    app = create_app(
        _settings(
            auth_enabled=True,
            api_keys={"viewer-key": ("viewer", "alice"), "operator-key": ("operator", "bob")},
        )
    )
    client = TestClient(app)
    create = client.post(
        "/incidents",
        json={
            "incident_id": "INC-AUTH-1",
            "device_id": "ventilator-01",
            "attack_type": "spoofing",
            "evidence_ref": "ref",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
        headers={"X-API-Key": "operator-key"},
    )
    assert create.status_code == 201

    # viewer role cannot set auto_approve=True -- 403, not 401 (they ARE
    # authenticated, they just lack the role this action needs).
    forbidden = client.post(
        "/incidents/INC-AUTH-1/investigate",
        json={"auto_approve": True},
        headers={"X-API-Key": "viewer-key"},
    )
    assert forbidden.status_code == 403
    assert "approver" in forbidden.json()["detail"]

    # operator role CAN investigate without auto-approving (fails later with
    # 503 -- no real LLM backend configured in this test -- but that 503,
    # not a 403, proves the role check itself passed).
    allowed = client.post(
        "/incidents/INC-AUTH-1/investigate",
        json={"auto_approve": False},
        headers={"X-API-Key": "operator-key"},
    )
    assert allowed.status_code == 503


def test_approving_an_execution_requires_approver_role():
    app = create_app(
        _settings(
            auth_enabled=True,
            api_keys={"operator-key": ("operator", "bob"), "approver-key": ("approver", "carol")},
        )
    )
    client = TestClient(app)
    body = {
        "incident_id": "INC-AUTH-2",
        "approval": {
            "incident_id": "INC-AUTH-2",
            "approver_identity": "bob",
            "decision": "approved",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    }

    # operator role supplying an approval -- 403 before the role check ever
    # gets to whether a proposed response even exists for this incident.
    forbidden = client.post(
        "/responses/executed", json=body, headers={"X-API-Key": "operator-key"}
    )
    assert forbidden.status_code == 403
    assert "approver" in forbidden.json()["detail"]

    # approver role clears the role gate -- fails with 404 (no proposed
    # response was ever created for this incident in this test), proving
    # the 403 above was really the role check and not some other rejection.
    allowed = client.post(
        "/responses/executed", json=body, headers={"X-API-Key": "approver-key"}
    )
    assert allowed.status_code == 404


def test_api_keys_parses_the_env_style_string_form():
    settings = Settings(api_keys="key1:viewer:alice,key2:approver:bob")
    assert settings.api_keys == {"key1": ("viewer", "alice"), "key2": ("approver", "bob")}


def test_api_keys_rejects_a_malformed_entry():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="key:role:identity"):
        Settings(api_keys="not-enough-parts")
