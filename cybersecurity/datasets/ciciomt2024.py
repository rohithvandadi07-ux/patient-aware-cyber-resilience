"""CICIoMT2024 dataset adapter.

Maps the Canadian Institute for Cybersecurity's IoMT benchmark onto this
project's canonical feature schema so that the detection pipeline, metrics
and experiment runners work on it unchanged.

Citation (required by the dataset's terms):

    S. Dadkhah, E. C. P. Neto, R. Ferreira, R. C. Molokwu, S. Sadeghi and
    A. A. Ghorbani, "CICIoMT2024: Attack Vectors in Healthcare devices - A
    Multi-Protocol Dataset for Assessing IoMT Device Security," Internet of
    Things, vol. 28, December 2024.

The dataset is NOT downloaded by this module. It must be obtained manually
from http://cicresearch.ca/IOTDataset/CICIoMT2024/ and placed under
``datasets/raw/ciciomt2024/``. See docs/datasets.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from backend.app.domain.enums import AttackType
from cybersecurity.schema import DatasetMeta, SplitProtocol

DEFAULT_ROOT = Path("datasets/raw/ciciomt2024")

# ---------------------------------------------------------------------------
# Native -> canonical feature mapping
# ---------------------------------------------------------------------------
#: Direct one-to-one renames. Native spellings are reproduced EXACTLY as the
#: dataset ships them, including the upstream misspelling of "Magnitue".
COLUMN_MAP: dict[str, str] = {
    "Rate": "packets_per_second",
    "Number": "packets",
    "Tot sum": "bytes",
    "Tot size": "mean_packet_bytes",
    "Duration": "flow_duration_s",
    "IAT": "mean_iat_ms",
    "Std": "iat_std_ms",
}

#: Features our schema declares that this dataset cannot provide. Recorded so
#: experiment reports state which parts of the threat model a benchmark run
#: can and cannot exercise, rather than silently imputing zeros.
UNAVAILABLE_FEATURES: tuple[str, ...] = (
    # host behaviour - no host telemetry in a network capture
    "cpu_pct",
    "disk_write_mb_s",
    "process_count",
    "encrypted_file_ops",
    # auth - no authentication events captured
    "failed_attempts",
    "auth_succeeded",
    "auth_after_failures",
    # command - no application-layer device commands captured
    "authenticated_session",
    "exceeds_safe_limit",
    "reduces_support",
    "delta_setpoint_abs",
    "source_offsegment",
    # device telemetry - no clinical telemetry captured
    "telemetry_residual",
    "telemetry_variance_ratio",
    "alarm_active",
    "missed_samples",
    # flow extras not present in this extraction
    "rtt_ms",
    "ttl_variance",
    "duplicate_mac_observed",
    "distinct_dst_ports",
    "distinct_dst_hosts",
    "dst_port_is_wellknown",
    "dst_port_is_iomt_service",
    "tls_downgrade",
)

# ---------------------------------------------------------------------------
# Label mapping: filename / native class -> our AttackType
# ---------------------------------------------------------------------------
LABEL_TO_ATTACK: dict[str, AttackType] = {
    "benign": AttackType.NONE,
    # TCP/IP DDoS
    "ddos-icmp": AttackType.DDOS,
    "ddos-syn": AttackType.DDOS,
    "ddos-tcp": AttackType.DDOS,
    "ddos-udp": AttackType.DDOS,
    # TCP/IP DoS
    "dos-icmp": AttackType.DOS,
    "dos-syn": AttackType.DOS,
    "dos-tcp": AttackType.DOS,
    "dos-udp": AttackType.DOS,
    # MQTT
    "mqtt-malformed": AttackType.MALICIOUS_COMMAND,
    "mqtt-ddos-connect": AttackType.DDOS,
    "mqtt-ddos-publish": AttackType.DDOS,
    "mqtt-dos-connect": AttackType.DOS,
    "mqtt-dos-publish": AttackType.DOS,
    # Recon
    "recon-ping-sweep": AttackType.RECONNAISSANCE,
    "recon-os-scan": AttackType.RECONNAISSANCE,
    "recon-port-scan": AttackType.PORT_SCAN,
    "recon-vulscan": AttackType.RECONNAISSANCE,
    # Spoofing
    "arp_spoofing": AttackType.ARP_SPOOFING,
}

#: Coarse 6-class family grouping used by the comparison literature.
SIX_CLASS_FAMILIES: dict[str, str] = {
    "benign": "Benign",
    "ddos": "DDoS",
    "dos": "DoS",
    "recon": "Recon",
    "mqtt": "MQTT",
    "arp": "Spoofing",
}


def _normalise_label(raw: str) -> str:
    """Normalise a filename or class string to a mapping key."""
    s = raw.lower().strip()
    s = re.sub(r"\.(csv|pcap|pcapng)$", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    s = s.replace("tcpip-", "").replace("tcp-ip-", "")
    s = re.sub(r"-+", "-", s).strip("-")
    if "arp" in s and "spoof" in s:
        return "arp_spoofing"
    if s.startswith("benign"):
        return "benign"
    # Collapse trailing capture-run indices. The dataset numbers repeated
    # captures both as a separate token ("ddos-syn-1") and glued to the
    # protocol ("DDoS-SYN1"), so strip both forms.
    s = re.sub(r"-\d+$", "", s)
    s = re.sub(r"(?<=[a-z])\d+$", "", s)
    if s.startswith("mqtt"):
        for key in (
            "mqtt-ddos-connect",
            "mqtt-ddos-publish",
            "mqtt-dos-connect",
            "mqtt-dos-publish",
            "mqtt-malformed",
        ):
            if s.startswith(key):
                return key
    return s


def _six_class(attack_key: str) -> str:
    if attack_key == "benign":
        return "Benign"
    if attack_key.startswith("arp"):
        return "Spoofing"
    if attack_key.startswith("mqtt"):
        return "MQTT"
    if attack_key.startswith("recon"):
        return "Recon"
    if attack_key.startswith("ddos"):
        return "DDoS"
    if attack_key.startswith("dos"):
        return "DoS"
    return "Unknown"


@dataclass
class CICIoMT2024Adapter:
    """Adapter for the Wi-Fi/MQTT CSV subset of CICIoMT2024."""

    root: Path = field(default_factory=lambda: DEFAULT_ROOT)
    meta: DatasetMeta = field(
        default_factory=lambda: DatasetMeta(
            name="CICIoMT2024",
            version="2024-12",
            source="http://cicresearch.ca/IOTDataset/CICIoMT2024/",
            licence="Research use; citation of the dataset paper required. "
            "No explicit licence published; UNB copyright asserted.",
            citation=(
                "S. Dadkhah, E. C. P. Neto, R. Ferreira, R. C. Molokwu, "
                "S. Sadeghi and A. A. Ghorbani, 'CICIoMT2024: Attack Vectors "
                "in Healthcare devices - A Multi-Protocol Dataset for "
                "Assessing IoMT Device Security,' Internet of Things, "
                "vol. 28, December 2024."
            ),
            requires_manual_download=True,
            local_path_hint=str(DEFAULT_ROOT / "WiFi_and_MQTT/attacks/csv"),
            native_split_protocol=SplitProtocol.PAPER_DEFINED,
            notes=(
                "Official train/test directories ship with the dataset and are "
                "used verbatim. Network-borne threats only: contains no host, "
                "auth, command or clinical-telemetry signals, so the host-level "
                "portion of our threat model cannot be exercised on it."
            ),
            base_paper=(
                "Comprehensive Feature Selection for Machine Learning-Based "
                "Intrusion Detection, SCITEPRESS 2025"
            ),
            base_paper_reported_metrics={
                "xgboost_binary_accuracy": 0.997,
                "xgboost_6class_accuracy": 0.977,
                "xgboost_19class_accuracy": 0.967,
            },
        )
    )

    # -- discovery ---------------------------------------------------------
    def csv_dir(self, split: str = "train") -> Path:
        return self.root / "WiFi_and_MQTT" / "attacks" / "csv" / split

    def available(self) -> bool:
        return any(self.csv_dir(s).is_dir() for s in ("train", "test"))

    def files(self, split: str = "train") -> list[Path]:
        d = self.csv_dir(split)
        return sorted(d.glob("*.csv")) if d.is_dir() else []

    # -- loading -----------------------------------------------------------
    def load(self, split: str = "train", max_rows_per_file: int | None = None) -> pd.DataFrame:
        """Load the split, deriving the class label from each filename.

        CICIoMT2024 ships one CSV per attack type, so the filename is the
        label. Rows carry no label column of their own.
        """
        paths = self.files(split)
        if not paths:
            raise FileNotFoundError(
                f"No CICIoMT2024 CSVs found in {self.csv_dir(split)}. "
                "Obtain the dataset manually (see docs/datasets.md); it is "
                "not downloaded automatically."
            )
        frames: list[pd.DataFrame] = []
        for p in paths:
            df = pd.read_csv(p, nrows=max_rows_per_file)
            df["__source_file"] = p.name
            df["__label_key"] = _normalise_label(p.stem)
            frames.append(df)
        return pd.concat(frames, ignore_index=True)

    # -- canonicalisation --------------------------------------------------
    def to_canonical(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Map native columns onto the canonical schema plus label columns."""
        out = pd.DataFrame(index=raw.index)

        for native, canonical in COLUMN_MAP.items():
            if native in raw.columns:
                out[canonical] = pd.to_numeric(raw[native], errors="coerce")

        # bytes_per_second derived from totals and duration
        if "Tot sum" in raw.columns and "Duration" in raw.columns:
            dur = pd.to_numeric(raw["Duration"], errors="coerce").replace(0, pd.NA)
            out["bytes_per_second"] = pd.to_numeric(raw["Tot sum"], errors="coerce") / dur

        # syn_ratio from SYN indicators
        if "syn_flag_number" in raw.columns:
            out["syn_ratio"] = pd.to_numeric(raw["syn_flag_number"], errors="coerce").clip(0, 1)
        elif "syn_count" in raw.columns and "Number" in raw.columns:
            n = pd.to_numeric(raw["Number"], errors="coerce").replace(0, pd.NA)
            out["syn_ratio"] = (pd.to_numeric(raw["syn_count"], errors="coerce") / n).clip(0, 1)

        # protocol one-hots: the dataset ships these as indicator columns
        for native, canonical in (
            ("TCP", "is_tcp"),
            ("UDP", "is_udp"),
            ("ARP", "is_arp"),
            ("ICMP", "is_icmp"),
        ):
            if native in raw.columns:
                out[canonical] = (pd.to_numeric(raw[native], errors="coerce").fillna(0) > 0).astype(
                    float
                )

        # ARP churn proxy: the ARP indicator is the only ARP signal present
        if "ARP" in raw.columns:
            out["arp_table_changes"] = (
                pd.to_numeric(raw["ARP"], errors="coerce").fillna(0) > 0
            ).astype(float)

        # Dataset-native features retained verbatim, namespaced so they are
        # never confused with canonical features.
        for native in (
            "Header_Length",
            "Protocol Type",
            "Magnitue",
            "Radius",
            "Covariance",
            "Variance",
            "Weight",
            "Min",
            "Max",
            "AVG",
        ):
            if native in raw.columns:
                key = "native_" + re.sub(r"[^a-z0-9]+", "_", native.lower()).strip("_")
                out[key] = pd.to_numeric(raw[native], errors="coerce")

        # -- labels --------------------------------------------------------
        keys = raw["__label_key"].astype(str)
        out["y_binary"] = (keys != "benign").astype(int)
        out["y_attack_type"] = keys.map(lambda k: LABEL_TO_ATTACK.get(k, AttackType.UNKNOWN).value)
        out["y_six_class"] = keys.map(_six_class)
        out["y_nineteen_class"] = keys
        out["__source_file"] = raw["__source_file"]

        return out.replace([float("inf"), float("-inf")], pd.NA)

    def label_mapping(self) -> dict[str, AttackType]:
        return dict(LABEL_TO_ATTACK)

    def unavailable_features(self) -> tuple[str, ...]:
        return UNAVAILABLE_FEATURES

    # -- reporting ---------------------------------------------------------
    def describe(self) -> dict[str, object]:
        return {
            "name": self.meta.name,
            "available": self.available(),
            "root": str(self.root),
            "train_files": len(self.files("train")),
            "test_files": len(self.files("test")),
            "unavailable_canonical_features": len(UNAVAILABLE_FEATURES),
            "citation": self.meta.citation,
            "published_baselines": self.meta.base_paper_reported_metrics,
        }


__all__ = [
    "COLUMN_MAP",
    "LABEL_TO_ATTACK",
    "SIX_CLASS_FAMILIES",
    "UNAVAILABLE_FEATURES",
    "CICIoMT2024Adapter",
]
