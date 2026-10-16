"""Tests for the real-data CICIoMT2024 loader and the metric helpers.

These build tiny CSVs with the dataset's real header and real file-naming
scheme in `tmp_path`; they do NOT need the real (multi-GB) dataset, and they
make no claim about model quality on it -- the real run is
`app/cybersecurity/train_ciciomt2024.py`, reported in `evaluation/`.
"""

import numpy as np
import pandas as pd
import pytest

from app.cybersecurity import ciciomt2024 as c
from app.cybersecurity.train_ciciomt2024 import binary_metrics, evaluate_all_views, multiclass_metrics


def _write_csv(path, n_rows, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(rng.random((n_rows, len(c.FEATURE_COLUMNS))), columns=c.FEATURE_COLUMNS)
    df.to_csv(path, index=False)


def test_there_are_19_classes_and_45_features():
    assert len(c.CLASS_NAMES) == 19
    assert len(set(c.CLASS_NAMES)) == 19
    assert len(c.FEATURE_COLUMNS) == 45
    assert len(set(c.FEATURE_COLUMNS)) == 45


@pytest.mark.parametrize(
    ("filename", "label"),
    [
        ("Benign_train.pcap.csv", "Benign"),
        ("TCP_IP-DDoS-UDP3_train.pcap.csv", "TCP_IP-DDoS-UDP"),
        ("TCP_IP-DDoS-ICMP8_train.pcap.csv", "TCP_IP-DDoS-ICMP"),
        ("TCP_IP-DoS-SYN_test.pcap.csv", "TCP_IP-DoS-SYN"),
        ("MQTT-DDoS-Connect_Flood_test.pcap.csv", "MQTT-DDoS-Connect_Flood"),
        ("Recon-Ping_Sweep_train.pcap.csv", "Recon-Ping_Sweep"),
        ("MQTT-Malformed_Data_test.pcap.csv", "MQTT-Malformed_Data"),
    ],
)
def test_label_from_filename_strips_the_capture_number(filename, label):
    assert c.label_from_filename(filename) == label


@pytest.mark.parametrize("bad", ["README.pdf", "Something-Else_train.pcap.csv", "Benign.csv"])
def test_label_from_filename_rejects_unknown_files(bad):
    with pytest.raises(ValueError):
        c.label_from_filename(bad)


def test_every_class_maps_to_a_known_family():
    for label in c.CLASS_NAMES:
        assert c.family_of(label) in c.FAMILY_NAMES
    assert c.family_of("MQTT-DoS-Publish_Flood") == "MQTT"
    assert c.family_of("TCP_IP-DoS-TCP") == "DoS"
    assert c.family_of("TCP_IP-DDoS-TCP") == "DDoS"
    assert c.family_of("Recon-VulScan") == "Recon"
    assert c.is_attack("ARP_Spoofing") and not c.is_attack("Benign")


def test_load_split_labels_rows_from_filenames_and_pools_numbered_captures(tmp_path):
    train = tmp_path / "train"
    train.mkdir()
    _write_csv(train / "Benign_train.pcap.csv", 5, seed=1)
    _write_csv(train / "TCP_IP-DDoS-UDP1_train.pcap.csv", 4, seed=2)
    _write_csv(train / "TCP_IP-DDoS-UDP2_train.pcap.csv", 6, seed=3)

    df = c.load_split(tmp_path, "train")

    assert len(df) == 15
    counts = df[c.LABEL_COLUMN].value_counts().to_dict()
    assert counts == {"Benign": 5, "TCP_IP-DDoS-UDP": 10}
    assert set(df[c.SOURCE_FILE_COLUMN]) == {
        "Benign_train.pcap.csv",
        "TCP_IP-DDoS-UDP1_train.pcap.csv",
        "TCP_IP-DDoS-UDP2_train.pcap.csv",
    }
    assert all(df[col].dtype == np.float32 for col in c.FEATURE_COLUMNS)


def test_load_split_accepts_the_split_folder_itself(tmp_path):
    _write_csv(tmp_path / "Benign_test.pcap.csv", 3)
    assert len(c.load_split(tmp_path, "test")) == 3


def test_load_split_errors_instead_of_returning_nothing(tmp_path):
    with pytest.raises(FileNotFoundError):
        c.load_split(tmp_path, "train")
    with pytest.raises(ValueError):
        c.load_split(tmp_path, "validation")


def test_load_split_rejects_a_csv_with_missing_feature_columns(tmp_path):
    pd.DataFrame({"Header_Length": [1.0]}).to_csv(tmp_path / "Benign_train.pcap.csv", index=False)
    with pytest.raises(ValueError, match="missing expected feature columns"):
        c.load_split(tmp_path, "train")


def test_max_rows_per_class_caps_big_classes_only_and_is_seeded(tmp_path):
    _write_csv(tmp_path / "Benign_train.pcap.csv", 3, seed=1)
    _write_csv(tmp_path / "TCP_IP-DoS-SYN1_train.pcap.csv", 50, seed=2)

    a = c.load_split(tmp_path, "train", max_rows_per_class=10, seed=7)
    b = c.load_split(tmp_path, "train", max_rows_per_class=10, seed=7)

    assert c.class_counts(a)["Benign"] == 3  # small class kept whole
    assert c.class_counts(a)["TCP_IP-DoS-SYN"] == 10
    pd.testing.assert_frame_equal(a, b)


def test_class_counts_reports_absent_classes_as_zero(tmp_path):
    _write_csv(tmp_path / "Benign_test.pcap.csv", 2)
    counts = c.class_counts(c.load_split(tmp_path, "test"))
    assert list(counts) == c.CLASS_NAMES
    assert counts["Benign"] == 2 and counts["ARP_Spoofing"] == 0


def test_perfect_predictions_give_perfect_metrics_in_every_view():
    y = np.array(["Benign", "ARP_Spoofing", "TCP_IP-DoS-SYN", "Benign"], dtype=object)
    views = evaluate_all_views(y, y.copy())
    assert views["19_class"]["accuracy"] == 1.0
    assert views["6_family"]["accuracy"] == 1.0
    b = views["binary_attack_vs_benign"]
    assert b["recall_attack_detection_rate"] == 1.0
    assert b["false_positive_rate_benign_flagged"] == 0.0


def test_binary_metrics_count_benign_flagged_as_false_positives():
    true = np.array(
        ["Benign", "Benign", "Benign", "Benign", "TCP_IP-DoS-SYN", "TCP_IP-DoS-SYN"], dtype=object
    )
    pred = np.array(["Benign", "Benign", "Benign", "ARP_Spoofing", "TCP_IP-DoS-SYN", "Benign"], dtype=object)
    b = binary_metrics(true, pred)
    assert b["confusion"] == {"tp": 1, "fn": 1, "fp": 1, "tn": 3}
    assert b["false_positive_rate_benign_flagged"] == pytest.approx(0.25)
    assert b["recall_attack_detection_rate"] == pytest.approx(0.5)
    assert b["precision"] == pytest.approx(0.5)


def test_family_view_forgives_confusion_within_a_family_but_19_class_does_not():
    true = np.array(["TCP_IP-DDoS-UDP", "TCP_IP-DDoS-SYN"], dtype=object)
    pred = np.array(["TCP_IP-DDoS-SYN", "TCP_IP-DDoS-SYN"], dtype=object)
    views = evaluate_all_views(true, pred)
    assert views["19_class"]["accuracy"] == pytest.approx(0.5)
    assert views["6_family"]["accuracy"] == pytest.approx(1.0)


def test_multiclass_metrics_include_all_labels_even_when_unseen():
    y = np.array(["Benign", "Benign"], dtype=object)
    m = multiclass_metrics(y, y.copy(), c.CLASS_NAMES)
    assert set(m["per_class"]) == set(c.CLASS_NAMES)
    assert m["per_class"]["ARP_Spoofing"]["support"] == 0


# --- validation split (used by the calibrated-gate experiment) ---------------


def _split_frame(tmp_path):
    train = tmp_path / "train"
    train.mkdir()
    _write_csv(train / "Benign_train.pcap.csv", 100, seed=1)
    _write_csv(train / "TCP_IP-DDoS-UDP1_train.pcap.csv", 30, seed=2)
    _write_csv(train / "TCP_IP-DDoS-UDP2_train.pcap.csv", 20, seed=3)
    _write_csv(train / "TCP_IP-DDoS-UDP3_train.pcap.csv", 10, seed=4)
    return c.load_split(tmp_path, "train")


def test_split_holds_out_the_last_whole_capture_for_multi_capture_classes(tmp_path):
    tr, va, info = c.split_train_validation(_split_frame(tmp_path))
    udp_val = va[va[c.LABEL_COLUMN] == "TCP_IP-DDoS-UDP"]
    assert set(udp_val[c.SOURCE_FILE_COLUMN]) == {"TCP_IP-DDoS-UDP3_train.pcap.csv"}
    assert len(udp_val) == 10
    assert "TCP_IP-DDoS-UDP3_train.pcap.csv" not in set(tr[c.SOURCE_FILE_COLUMN])
    assert info["TCP_IP-DDoS-UDP"]["method"] == "held-out capture"


def test_split_uses_a_contiguous_tail_block_with_a_gap_for_single_capture_classes(tmp_path):
    frame = _split_frame(tmp_path)
    tr, va, info = c.split_train_validation(frame, val_fraction=0.2, gap_fraction=0.05)
    benign = frame[frame[c.LABEL_COLUMN] == "Benign"]
    b_tr, b_va = tr[tr[c.LABEL_COLUMN] == "Benign"], va[va[c.LABEL_COLUMN] == "Benign"]
    assert len(b_va) == 20 and len(b_tr) == 80 - 5  # 20% validation, 5% gap dropped
    # validation is exactly the last 20 rows of the capture, in order; train the first 75
    pd.testing.assert_frame_equal(b_va.reset_index(drop=True), benign.iloc[80:].reset_index(drop=True))
    pd.testing.assert_frame_equal(b_tr.reset_index(drop=True), benign.iloc[:75].reset_index(drop=True))
    assert info["Benign"]["dropped_gap_rows"] == 5


def test_split_never_overlaps_and_rejects_a_bad_fraction(tmp_path):
    frame = _split_frame(tmp_path)
    tr, va, _ = c.split_train_validation(frame)
    assert len(tr) + len(va) <= len(frame)
    assert not set(map(tuple, tr[c.FEATURE_COLUMNS].to_numpy())) & set(
        map(tuple, va[c.FEATURE_COLUMNS].to_numpy())
    )
    with pytest.raises(ValueError):
        c.split_train_validation(frame, val_fraction=0.7)


def test_cap_rows_per_class_is_public_and_matches_load_split(tmp_path):
    _write_csv(tmp_path / "TCP_IP-DoS-SYN1_train.pcap.csv", 50, seed=2)
    full = c.load_split(tmp_path, "train")
    capped = c.cap_rows_per_class(full, 10, seed=7)
    pd.testing.assert_frame_equal(capped, c.load_split(tmp_path, "train", max_rows_per_class=10, seed=7))
