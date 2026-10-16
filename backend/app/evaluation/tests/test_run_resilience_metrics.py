import numpy as np
import pytest

from app.evaluation.run_resilience_metrics import (
    containment_profile,
    decision_path_latency,
    detection_delay_per_capture,
    percentile_stats,
)


def test_percentile_stats_orders_correctly():
    s = percentile_stats(list(range(1, 101)))
    assert s["n"] == 100 and s["p50_ms"] <= s["p95_ms"] <= s["p99_ms"] <= s["max_ms"] == 100


def test_decision_path_latency_is_measured_and_small():
    s = decision_path_latency(n=50)
    assert s["n"] == 50 and 0 < s["p50_ms"] < 1000


def test_detection_delay_counts_flows_to_first_alert_and_skips_benign_captures():
    sources = np.array(["a"] * 6 + ["b"] * 4 + ["c"] * 3, dtype=object)
    true19 = np.array(["Benign"] * 6 + ["TCP_IP-DoS-SYN"] * 4 + ["ARP_Spoofing"] * 3, dtype=object)
    detected = np.array([False] * 6 + [False, False, True, True] + [False, False, False])
    caps = detection_delay_per_capture(sources, true19, detected)
    assert [c["capture"] for c in caps] == ["b", "c"]  # benign capture 'a' skipped
    b, c = caps
    assert b["first_alert_flow_index"] == 2 and b["share_of_flows_alerted"] == 0.5
    assert b["alerted_within_10_flows"] and b["alerted_within_100_flows"]
    assert c["first_alert_flow_index"] is None and not c["alerted_within_10_flows"]


def test_containment_profile_splits_missed_autonomous_and_waiting():
    # 5 real attacks: 1 missed, 2 contained on their own, 2 waiting; plus 1 benign false alarm.
    p = {
        "attack": np.array([1, 1, 1, 1, 1, 0], dtype=bool),
        "fired": np.array([0, 1, 1, 1, 1, 1], dtype=bool),
        "high_stakes": np.array([0, 0, 0, 1, 1, 0], dtype=bool),
    }
    executed = np.array([0, 1, 1, 0, 0, 1], dtype=bool)
    prof = containment_profile(p, executed, pipeline_ms=2.0)
    g = prof["all_devices"]
    assert (g["real_attacks"], g["missed_by_detector"], g["alerted"]) == (5, 1, 4)
    assert (g["contained_autonomously"], g["waiting_for_human"]) == (2, 2)
    assert g["share_of_alerts_waiting_for_human"] == pytest.approx(0.5)
    # delay = pipeline + share * D: 0.002 + 0.5 * 60 s for D = 1 min
    assert g["modelled_mean_containment_delay_seconds"]["1"] == pytest.approx(0.002 + 30.0)
    hs = prof["high_stakes_devices"]
    assert hs["alerted"] == 2 and hs["share_of_alerts_waiting_for_human"] == 1.0


def test_containment_profile_with_no_alerts_reports_none_not_zero():
    p = {"attack": np.array([1, 1], dtype=bool), "fired": np.zeros(2, bool), "high_stakes": np.zeros(2, bool)}
    g = containment_profile(p, np.zeros(2, bool), 1.0)["all_devices"]
    assert g["share_of_alerts_waiting_for_human"] is None
    assert g["modelled_mean_containment_delay_seconds"]["5"] is None
