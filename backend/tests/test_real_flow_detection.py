"""Tests for the real-flow (45-feature, 19-class) runtime detector and its
`/detections/score-flows` endpoint.

The models here are tiny stand-ins trained on random 45-column data: they test
the plumbing (validation, label decoding, threshold, label->category mapping,
incident creation), NOT detection quality. Quality on the real data is
`evaluation/ciciomt2024_results.md`.
"""

import json

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from app.api.detections import get_real_flow_service
from app.core.config import Settings, get_settings
from app.cybersecurity.ciciomt2024 import CLASS_NAMES, FEATURE_COLUMNS
from app.cybersecurity.real_flow_detection import (
    FAMILY_TO_ATTACK_CATEGORY,
    InvalidFlowError,
    RealFlowDetectionService,
    flows_to_matrix,
)
from app.main import app
from app.schemas.enums import AttackCategory, ImpactLevel

client = TestClient(app)


def _flow(value: float) -> dict[str, float]:
    return {c: value for c in FEATURE_COLUMNS}


def _toy_data(rows_per_class: int = 6):
    """Class k lives around value k, so the toy model separates classes well."""
    rng = np.random.default_rng(0)
    X = np.concatenate([rng.normal(k, 0.05, (rows_per_class, 45)) for k in range(19)]).astype(np.float32)
    y = np.repeat(np.arange(19), rows_per_class)
    return X, y


@pytest.fixture(scope="module")
def xgb_service():
    X, y = _toy_data()
    model = XGBClassifier(n_estimators=10, max_depth=3, objective="multi:softprob", tree_method="hist")
    model.fit(X, y)
    return RealFlowDetectionService(model, list(CLASS_NAMES), "toy_xgb")


@pytest.fixture(scope="module")
def rf_service():
    X, y = _toy_data()
    model = RandomForestClassifier(n_estimators=20, random_state=0)
    model.fit(X, np.array(CLASS_NAMES, dtype=object)[y])
    return RealFlowDetectionService(model, list(CLASS_NAMES), "toy_rf")


def test_every_attack_family_maps_to_an_attack_category():
    assert set(FAMILY_TO_ATTACK_CATEGORY) == {"ARP_Spoofing", "MQTT", "Recon", "DoS", "DDoS"}
    assert FAMILY_TO_ATTACK_CATEGORY["ARP_Spoofing"] is AttackCategory.SPOOFING
    assert FAMILY_TO_ATTACK_CATEGORY["MQTT"] is AttackCategory.MQTT_BASED


def test_flows_to_matrix_orders_columns_and_rejects_bad_input():
    flow = _flow(1.0)
    flow[FEATURE_COLUMNS[-1]] = 7.0
    m = flows_to_matrix([flow])
    assert m.shape == (1, 45) and m.dtype == np.float32 and m[0, -1] == 7.0

    with pytest.raises(InvalidFlowError, match="at least one"):
        flows_to_matrix([])
    missing = _flow(1.0)
    del missing["Rate"]
    with pytest.raises(InvalidFlowError, match="missing"):
        flows_to_matrix([missing])
    bad = _flow(1.0)
    bad["Rate"] = float("nan")
    with pytest.raises(InvalidFlowError, match="non-finite"):
        flows_to_matrix([bad])


@pytest.mark.parametrize("service_name", ["xgb_service", "rf_service"])
def test_benign_flow_emits_no_detection_and_attack_flow_does(service_name, request):
    service = request.getfixturevalue(service_name)
    benign, arp, dos_syn = _flow(0.0), _flow(1.0), _flow(float(CLASS_NAMES.index("TCP_IP-DoS-SYN")))
    results = service.score_flows("dev-1", [benign, arp, dos_syn])

    assert [r.predicted_class for r in results] == ["Benign", "ARP_Spoofing", "TCP_IP-DoS-SYN"]
    assert results[0].detection is None
    assert results[1].detection.attack_type is AttackCategory.SPOOFING
    assert results[2].detection.attack_type is AttackCategory.DOS
    assert results[2].family == "DoS"
    assert results[2].detection.device_id == "dev-1"
    assert "TCP_IP-DoS-SYN" in results[2].detection.evidence_ref


def test_below_threshold_detections_are_suppressed_but_still_reported(xgb_service):
    strict = RealFlowDetectionService(
        xgb_service._estimator, list(CLASS_NAMES), "toy_xgb", confidence_threshold=1.01
    )
    result = strict.score_flows("dev-1", [_flow(1.0)])[0]
    assert result.predicted_class == "ARP_Spoofing" and result.detection is None


def test_severity_follows_confidence_cutoff(xgb_service):
    result = xgb_service.score_flows("dev-1", [_flow(1.0)])[0]
    expected = ImpactLevel.CRITICAL if result.confidence >= 0.85 else ImpactLevel.HIGH
    assert result.detection.severity_hint is expected


def test_service_rejects_wrong_label_set_and_models_without_proba():
    with pytest.raises(ValueError, match="19"):
        RealFlowDetectionService(object.__new__(RandomForestClassifier), ["a", "b"], "x")
    with pytest.raises(TypeError, match="predict_proba"):
        RealFlowDetectionService(object(), list(CLASS_NAMES), "x")


def test_from_artifact_roundtrip_and_error_paths(tmp_path, xgb_service):
    path = tmp_path / "ciciomt2024_toy.joblib"
    with pytest.raises(FileNotFoundError, match="train_ciciomt2024"):
        RealFlowDetectionService.from_artifact(path)

    joblib.dump(xgb_service._estimator, path)
    with pytest.raises(FileNotFoundError, match="metadata"):
        RealFlowDetectionService.from_artifact(path)

    meta = {"model_name": "toy", "labels": CLASS_NAMES, "feature_columns": FEATURE_COLUMNS}
    (tmp_path / "ciciomt2024_toy.metadata.json").write_text(json.dumps(meta))
    loaded = RealFlowDetectionService.from_artifact(path)
    assert loaded.score_flows("d", [_flow(1.0)])[0].predicted_class == "ARP_Spoofing"

    meta["feature_columns"] = FEATURE_COLUMNS[:-1]
    (tmp_path / "ciciomt2024_toy.metadata.json").write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="feature columns"):
        RealFlowDetectionService.from_artifact(path)


# ------------------------------------------------------------------ endpoint


def test_score_flows_without_model_returns_503(tmp_path):
    # Point at a path with no artifact (the real one may well exist on a dev machine).
    missing = Settings(real_detector_model_path=str(tmp_path / "nope.joblib"))
    app.dependency_overrides[get_settings] = lambda: missing
    try:
        response = client.post("/detections/score-flows", json={"device_id": "d", "flows": [_flow(1.0)]})
    finally:
        app.dependency_overrides.pop(get_settings, None)
    assert response.status_code == 503
    assert "train_ciciomt2024" in response.json()["detail"]


def test_score_flows_opens_one_incident_per_attack_type(xgb_service):
    app.dependency_overrides[get_real_flow_service] = lambda: xgb_service
    try:
        flood = float(CLASS_NAMES.index("TCP_IP-DDoS-UDP"))
        body = {
            "device_id": "ventilator-01",
            "flows": [_flow(0.0), _flow(flood), _flow(flood), _flow(flood), _flow(1.0)],
        }
        response = client.post("/detections/score-flows", json=body)
        assert response.status_code == 200
        data = response.json()
        assert len(data["verdicts"]) == 5
        assert [v["family"] for v in data["verdicts"]] == ["Benign", "DDoS", "DDoS", "DDoS", "ARP_Spoofing"]
        assert data["verdicts"][0]["detection"] is None
        assert len(data["incident_ids"]) == 2  # a 3-flow flood is ONE incident, plus the ARP one

        incident = client.get(f"/incidents/{data['incident_ids'][0]}")
        assert incident.status_code == 200 and incident.json()["device_id"] == "ventilator-01"
    finally:
        app.dependency_overrides.pop(get_real_flow_service, None)


def test_score_flows_rejects_incomplete_flows_with_422(xgb_service):
    app.dependency_overrides[get_real_flow_service] = lambda: xgb_service
    try:
        short = {"Rate": 1.0}
        response = client.post("/detections/score-flows", json={"device_id": "d", "flows": [short]})
        assert response.status_code == 422
        assert "missing" in response.json()["detail"]
        assert client.post("/detections/score-flows", json={"device_id": "d", "flows": []}).status_code == 422
    finally:
        app.dependency_overrides.pop(get_real_flow_service, None)
