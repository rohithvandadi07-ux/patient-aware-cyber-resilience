"""CICIoMT2024 adapter tests.

These run without the dataset present: the adapter's contract (label
normalisation, canonical mapping, leakage hygiene) is testable on synthetic
frames shaped like the real CSVs. Tests needing the real files are marked
``requires_dataset`` and skip cleanly.
"""

from __future__ import annotations

import pandas as pd
import pytest

from backend.app.domain.enums import AttackType
from cybersecurity.datasets.ciciomt2024 import (
    LABEL_TO_ATTACK,
    CICIoMT2024Adapter,
    _normalise_label,
    _six_class,
)
from cybersecurity.schema import FEATURE_NAMES, FORBIDDEN_FEATURES, assert_no_leakage

pytestmark = pytest.mark.unit


class TestLabelNormalisation:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("Benign_train", "benign"),
            ("Benign", "benign"),
            ("TCP_IP-DDoS-SYN1", "ddos-syn"),
            ("TCP_IP-DDoS-SYN", "ddos-syn"),
            ("TCP_IP-DoS-ICMP3", "dos-icmp"),
            ("TCP_IP-DDoS-UDP2", "ddos-udp"),
            ("TCP_IP-DoS-TCP", "dos-tcp"),
            ("ARP_Spoofing", "arp_spoofing"),
            ("arp spoofing", "arp_spoofing"),
            ("MQTT-DoS-Publish_Flood", "mqtt-dos-publish"),
            ("MQTT-DDoS-Connect_Flood", "mqtt-ddos-connect"),
            ("MQTT-Malformed_Data", "mqtt-malformed"),
            ("Recon-Port_Scan", "recon-port-scan"),
            ("Recon-OS_Scan", "recon-os-scan"),
            ("Recon-VulScan", "recon-vulscan"),
            ("Recon-Ping_Sweep", "recon-ping-sweep"),
        ],
    )
    def test_normalisation(self, filename: str, expected: str) -> None:
        assert _normalise_label(filename) == expected

    def test_every_mapped_key_resolves_to_a_known_attack(self) -> None:
        """No normalised key may fall through to UNKNOWN silently."""
        for key in LABEL_TO_ATTACK:
            assert LABEL_TO_ATTACK[key] is not AttackType.UNKNOWN or key == "unknown"

    @pytest.mark.parametrize(
        ("filename", "family"),
        [
            ("Benign", "Benign"),
            ("TCP_IP-DDoS-SYN1", "DDoS"),
            ("TCP_IP-DoS-ICMP", "DoS"),
            ("Recon-Port_Scan", "Recon"),
            ("MQTT-Malformed_Data", "MQTT"),
            ("ARP_Spoofing", "Spoofing"),
        ],
    )
    def test_six_class_families(self, filename: str, family: str) -> None:
        assert _six_class(_normalise_label(filename)) == family

    def test_six_class_has_exactly_the_published_families(self) -> None:
        """Must match the 6-class task used by the comparison literature."""
        names = [
            "Benign",
            "TCP_IP-DDoS-SYN",
            "TCP_IP-DoS-SYN",
            "Recon-OS_Scan",
            "MQTT-Malformed_Data",
            "ARP_Spoofing",
        ]
        families = {_six_class(_normalise_label(n)) for n in names}
        assert families == {"Benign", "DDoS", "DoS", "Recon", "MQTT", "Spoofing"}


def _synthetic_raw(label_file: str, n: int = 5) -> pd.DataFrame:
    """A frame shaped like a real CICIoMT2024 CSV."""
    return pd.DataFrame(
        {
            "Header_Length": [54.0] * n,
            "Protocol Type": [6.0] * n,
            "Duration": [1.0] * n,
            "Rate": [1200.0] * n,
            "Srate": [1200.0] * n,
            "syn_flag_number": [1.0] * n,
            "syn_count": [120.0] * n,
            "ack_count": [3.0] * n,
            "TCP": [1.0] * n,
            "UDP": [0.0] * n,
            "ARP": [0.0] * n,
            "ICMP": [0.0] * n,
            "Tot sum": [96000.0] * n,
            "Tot size": [80.0] * n,
            "IAT": [0.83] * n,
            "Number": [1200.0] * n,
            "Min": [54.0] * n,
            "Max": [120.0] * n,
            "AVG": [80.0] * n,
            "Std": [12.0] * n,
            "Magnitue": [9.0] * n,
            "Variance": [144.0] * n,
            "__source_file": [label_file] * n,
            "__label_key": [_normalise_label(label_file.replace(".csv", ""))] * n,
        }
    )


class TestCanonicalisation:
    def test_maps_onto_canonical_feature_names(self) -> None:
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("TCP_IP-DDoS-SYN1.csv"))
        mapped = {c for c in out.columns if c in FEATURE_NAMES}
        assert "packets_per_second" in mapped
        assert "mean_iat_ms" in mapped
        assert "syn_ratio" in mapped
        assert "is_tcp" in mapped

    def test_derives_bytes_per_second(self) -> None:
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("Benign.csv"))
        assert out["bytes_per_second"].iloc[0] == pytest.approx(96000.0)

    def test_produces_all_label_columns(self) -> None:
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("TCP_IP-DDoS-SYN1.csv"))
        assert out["y_binary"].iloc[0] == 1
        assert out["y_attack_type"].iloc[0] == AttackType.DDOS.value
        assert out["y_six_class"].iloc[0] == "DDoS"
        assert out["y_nineteen_class"].iloc[0] == "ddos-syn"

    def test_benign_is_labelled_zero(self) -> None:
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("Benign.csv"))
        assert out["y_binary"].iloc[0] == 0
        assert out["y_attack_type"].iloc[0] == AttackType.NONE.value

    def test_no_label_resolves_to_unknown_for_real_filenames(self) -> None:
        """Guards against a mapping gap passing silently as UNKNOWN."""
        real_names = [
            "Benign",
            "ARP_Spoofing",
            "TCP_IP-DDoS-SYN1",
            "TCP_IP-DDoS-TCP1",
            "TCP_IP-DDoS-ICMP1",
            "TCP_IP-DDoS-UDP1",
            "TCP_IP-DoS-SYN1",
            "TCP_IP-DoS-TCP1",
            "TCP_IP-DoS-ICMP1",
            "TCP_IP-DoS-UDP1",
            "MQTT-DDoS-Connect_Flood",
            "MQTT-DDoS-Publish_Flood",
            "MQTT-DoS-Connect_Flood",
            "MQTT-DoS-Publish_Flood",
            "MQTT-Malformed_Data",
            "Recon-Ping_Sweep",
            "Recon-OS_Scan",
            "Recon-Port_Scan",
            "Recon-VulScan",
        ]
        unmapped = [
            n
            for n in real_names
            if LABEL_TO_ATTACK.get(_normalise_label(n), AttackType.UNKNOWN) is AttackType.UNKNOWN
        ]
        assert unmapped == [], f"unmapped CICIoMT2024 classes: {unmapped}"
        assert len(real_names) == 19, "19-class task must cover 19 classes"

    def test_native_features_are_namespaced(self) -> None:
        """Dataset-specific columns must not masquerade as canonical ones."""
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("Benign.csv"))
        native = [c for c in out.columns if c.startswith("native_")]
        assert "native_header_length" in native
        assert "native_magnitue" in native
        for c in native:
            assert c not in FEATURE_NAMES


class TestLeakageHygiene:
    def test_canonical_output_carries_no_forbidden_feature(self) -> None:
        out = CICIoMT2024Adapter().to_canonical(_synthetic_raw("TCP_IP-DoS-UDP1.csv"))
        feature_cols = [c for c in out.columns if not c.startswith(("y_", "__"))]
        assert_no_leakage(feature_cols)

    def test_label_columns_are_recognised_as_forbidden(self) -> None:
        """The label names we emit must be caught if they reach a model."""
        assert "label" in FORBIDDEN_FEATURES
        with pytest.raises(ValueError, match="Leaking columns"):
            assert_no_leakage(["packets_per_second", "label"])

    def test_declares_which_canonical_features_it_cannot_supply(self) -> None:
        a = CICIoMT2024Adapter()
        missing = set(a.unavailable_features())
        assert missing, "adapter must declare unavailable features"
        assert missing <= set(FEATURE_NAMES)
        # It is a network capture: no host, auth, command or clinical signal.
        for f in ("cpu_pct", "authenticated_session", "telemetry_residual", "failed_attempts"):
            assert f in missing


class TestAvailabilityHandling:
    def test_reports_unavailable_without_files(self) -> None:
        a = CICIoMT2024Adapter(root=__import__("pathlib").Path("/nonexistent"))
        assert a.available() is False
        assert a.describe()["available"] is False

    def test_load_raises_actionable_error_when_absent(self) -> None:
        a = CICIoMT2024Adapter(root=__import__("pathlib").Path("/nonexistent"))
        with pytest.raises(FileNotFoundError, match="docs/datasets.md"):
            a.load("train")

    def test_metadata_records_citation_and_published_baselines(self) -> None:
        m = CICIoMT2024Adapter().meta
        assert "Dadkhah" in m.citation
        assert m.requires_manual_download is True
        assert m.base_paper_reported_metrics["xgboost_binary_accuracy"] == 0.997


@pytest.mark.requires_dataset
class TestWithRealDataset:
    """Skipped unless the licensed dataset has been placed locally."""

    def test_real_files_canonicalise(self) -> None:
        a = CICIoMT2024Adapter()
        if not a.available():
            pytest.skip("CICIoMT2024 not present; see docs/datasets.md")
        raw = a.load("train", max_rows_per_file=50)
        out = a.to_canonical(raw)
        assert len(out) > 0
        assert set(out["y_binary"].unique()) <= {0, 1}
