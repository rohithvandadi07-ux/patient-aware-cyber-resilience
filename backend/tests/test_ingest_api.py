"""`/ingest/alerts` API tests. Own `create_app()` instance, like the other API tests."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.app_factory import create_app
from app.core.config import Settings, get_settings

app = create_app()
client = TestClient(app)


@pytest.fixture
def ip_map():
    app.dependency_overrides[get_settings] = lambda: Settings(
        device_ip_map={"10.0.1.20": "ventilator-01", "10.0.1.30": "ecg-monitor-01"}
    )
    yield
    app.dependency_overrides.pop(get_settings, None)


def suricata(dest="10.0.1.20", signature="ET DOS SYN flood", category="Attempted Denial of Service", severity=1):
    return {
        "timestamp": "2026-10-19T10:00:00.123456+0000", "event_type": "alert", "flow_id": 7,
        "src_ip": "10.0.0.9", "dest_ip": dest, "proto": "TCP",
        "alert": {"signature": signature, "category": category, "severity": severity, "signature_id": 2001},
    }


def post(body):
    return client.post("/ingest/alerts", json=body)


def test_generic_alert_opens_a_detected_incident():
    r = post({"source": "generic", "alerts": [
        {"device_id": "infusion-pump-01", "attack_type": "dos", "confidence": 0.9}]})
    assert r.status_code == 200
    body = r.json()
    assert len(body["incident_ids"]) == 1
    incident = client.get(f"/incidents/{body['incident_ids'][0]}").json()
    assert incident["device_id"] == "infusion-pump-01" and incident["status"] == "detected"
    assert body["outcomes"][0]["status"] == "accepted"


def test_alert_becomes_evidence_the_agents_can_see():
    r = post({"source": "generic", "alerts": [
        {"device_id": "ecg-monitor-01", "attack_type": "spoofing", "description": "ARP poisoning seen"}]})
    iid = r.json()["incident_ids"][0]
    evidence = client.get(f"/incidents/{iid}/evidence")
    assert evidence.status_code == 200
    assert "external_alert:spoofing" in evidence.text


def test_suricata_batch_deduplicates_to_one_incident_per_device_and_type(ip_map):
    r = post({"source": "suricata_eve", "alerts": [suricata(severity=2), suricata(severity=1), suricata(severity=3)]})
    body = r.json()
    assert len(body["incident_ids"]) == 1
    assert {o["incident_id"] for o in body["outcomes"]} == {body["incident_ids"][0]}
    assert {o["device_id"] for o in body["outcomes"]} == {"ventilator-01"}
    assert [o["confidence"] for o in body["outcomes"]] == [0.75, 0.90, 0.60]


def test_different_types_or_devices_open_separate_incidents(ip_map):
    r = post({"source": "suricata_eve", "alerts": [
        suricata(), suricata(signature="ET SCAN Nmap", category="Network Scan"), suricata(dest="10.0.1.30")]})
    assert len(r.json()["incident_ids"]) == 3


def test_ignored_rejected_and_unmatched_are_reported_and_open_nothing(ip_map):
    r = post({"source": "suricata_eve", "alerts": [
        {"event_type": "flow", "timestamp": "2026-10-19T10:00:00+0000"},
        {"event_type": "alert"},
        suricata(dest="192.168.9.9"),
    ]})
    body = r.json()
    assert [o["status"] for o in body["outcomes"]] == ["ignored", "rejected", "rejected"]
    assert "no registered device" in body["outcomes"][2]["reason"]
    assert body["incident_ids"] == []


def test_wazuh_agent_name_identifies_the_device():
    r = post({"source": "wazuh", "alerts": [{
        "rule": {"id": "1", "level": 12, "description": "MQTT flood detected"},
        "agent": {"name": "ventilator-01"}, "timestamp": "2026-10-19T10:00:00.000+0000"}]})
    outcome = r.json()["outcomes"][0]
    assert outcome["device_id"] == "ventilator-01" and outcome["attack_type"] == "mqtt_based"


def test_explicit_device_id_applies_and_unknown_is_404():
    ok = post({"source": "wazuh", "device_id": "ecg-monitor-01",
               "alerts": [{"rule": {"level": 8, "description": "port scan"}}]})
    assert ok.json()["outcomes"][0]["device_id"] == "ecg-monitor-01"
    assert post({"source": "wazuh", "device_id": "nope", "alerts": [{"rule": {"level": 8}}]}).status_code == 404


def test_request_validation():
    assert post({"source": "generic", "alerts": []}).status_code == 422
    assert post({"source": "snort", "alerts": [{}]}).status_code == 422


def test_device_ip_map_parsing():
    s = Settings(device_ip_map="10.0.1.30=ecg-monitor-01, 10.0.1.20=ventilator-01")
    assert s.device_ip_map == {"10.0.1.30": "ecg-monitor-01", "10.0.1.20": "ventilator-01"}
    assert Settings(device_ip_map='{"1.2.3.4": "x"}').device_ip_map == {"1.2.3.4": "x"}
    assert Settings(device_ip_map="").device_ip_map == {}
    with pytest.raises(ValidationError):
        Settings(device_ip_map="no-equals-sign")
