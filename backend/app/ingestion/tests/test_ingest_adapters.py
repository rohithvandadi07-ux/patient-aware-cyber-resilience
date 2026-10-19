import pytest

from app.ingestion.adapters import (
    AlertParseError,
    NotAnAlertError,
    classify_attack,
    parse_generic,
    parse_suricata_eve,
    parse_timestamp,
    parse_wazuh,
)


def suricata(**alert):
    base = {"signature": "ET DOS Possible SYN flood", "category": "Attempted Denial of Service",
            "severity": 1, "signature_id": 2001}
    base.update(alert)
    return {"timestamp": "2026-10-19T10:00:00.123456+0000", "event_type": "alert", "flow_id": 42,
            "src_ip": "10.0.0.9", "dest_ip": "10.0.1.20", "proto": "TCP", "alert": base}


def test_suricata_dos_alert_maps_to_dos_with_high_severity():
    a = parse_suricata_eve(suricata())
    assert a.attack_type.value == "dos"
    assert a.confidence == 0.90 and a.severity_hint.value == "high"
    assert a.timestamp.tzinfo is not None and a.timestamp.year == 2026
    assert a.candidates == ("10.0.1.20", "10.0.0.9")
    assert a.reference.startswith("suricata:flow=42:sid=2001")


def test_suricata_scan_medium_severity():
    a = parse_suricata_eve(suricata(signature="ET SCAN Nmap", category="Network Scan", severity=2))
    assert a.attack_type.value == "reconnaissance"
    assert a.confidence == 0.75 and a.severity_hint.value == "medium"


def test_suricata_mqtt_and_unknown():
    mqtt = parse_suricata_eve(suricata(signature="MQTT CONNECT flood", category="x"))
    assert mqtt.attack_type.value == "mqtt_based"
    odd = parse_suricata_eve(suricata(signature="Something odd", category="Misc"))
    assert odd.attack_type.value == "unknown"


def test_suricata_non_alert_is_skipped_not_rejected_as_malformed():
    with pytest.raises(NotAnAlertError):
        parse_suricata_eve({"event_type": "flow", "timestamp": "2026-10-19T10:00:00+0000"})


def test_suricata_malformed_is_rejected():
    with pytest.raises(AlertParseError):
        parse_suricata_eve({"event_type": "alert"})
    with pytest.raises(AlertParseError):
        parse_suricata_eve(suricata(severity="loud"))
    with pytest.raises(AlertParseError):
        parse_suricata_eve("not an object")


def test_wazuh_level_drives_confidence_and_candidates():
    a = parse_wazuh({
        "id": "1700000000.1", "timestamp": "2026-10-19T10:00:00.000+0000",
        "rule": {"id": "100100", "level": 12, "description": "ARP spoofing detected", "groups": ["network"]},
        "agent": {"id": "003", "name": "ecg-monitor-01", "ip": "10.0.1.30"},
        "data": {"srcip": "10.0.0.66"},
    })
    assert a.attack_type.value == "spoofing"
    assert a.confidence == 0.90 and a.severity_hint.value == "high"
    assert "ecg-monitor-01" in a.candidates and "10.0.1.30" in a.candidates
    assert a.reference.startswith("wazuh:1700000000.1")


def test_wazuh_low_level_and_missing_level():
    low = parse_wazuh({"rule": {"level": 3, "description": "login failure"}})
    assert low.confidence == 0.50 and low.severity_hint.value == "low"
    with pytest.raises(AlertParseError):
        parse_wazuh({"rule": {"description": "no level"}})
    with pytest.raises(AlertParseError):
        parse_wazuh({"no_rule": True})


def test_generic_defaults_and_validation():
    a = parse_generic({"device_id": "infusion-pump-01", "attack_type": "dos"})
    assert a.confidence == 0.8 and a.severity_hint.value == "medium" and a.candidates == ("infusion-pump-01",)
    with pytest.raises(AlertParseError):
        parse_generic({"device_id": "d", "attack_type": "not_a_class"})
    with pytest.raises(AlertParseError):
        parse_generic({"device_id": "d", "attack_type": "dos", "confidence": 1.5})
    with pytest.raises(AlertParseError):
        parse_generic({"device_id": "d", "attack_type": "dos", "severity": "extreme"})


def test_timestamp_forms_and_rejection():
    assert parse_timestamp("2026-10-19T10:00:00.5+0000").utcoffset().total_seconds() == 0
    assert parse_timestamp("2026-10-19T10:00:00Z").tzinfo is not None
    assert parse_timestamp("2026-10-19T10:00:00").tzinfo is not None
    assert parse_timestamp(None).tzinfo is not None
    with pytest.raises(AlertParseError):
        parse_timestamp("yesterday-ish")


def test_classifier_does_not_overreach():
    assert classify_attack("Windows update service started").value == "unknown"
    assert classify_attack("Distributed denial of service").value == "ddos"
