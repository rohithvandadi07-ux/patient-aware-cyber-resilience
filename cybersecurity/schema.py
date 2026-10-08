"""Detection feature-schema contract.

WHY THIS EXISTS
---------------
Detection must be trainable on (a) the simulator's event stream and (b) a
public benchmark dataset chosen from the base paper(s) we compare against,
*without* rewriting the model layer for each. So the pipeline is defined
against a declared schema contract rather than against any one dataset's
column names.

Adding a benchmark dataset is therefore a contained change: implement a
:class:`DatasetAdapter` that maps the dataset's native columns onto
:data:`CANONICAL_FEATURES`, declare its split protocol, and the existing
models, metrics and experiment runners work unchanged.

CRITICAL: the schema deliberately excludes any field that encodes the label
or the device's identity, because both leak. See ``FORBIDDEN_FEATURES``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import pandas as pd

from backend.app.domain.enums import AttackType, StrEnum


class FeatureFamily(StrEnum):
    """Grouping used for ablation ("which signal families matter?")."""

    FLOW_VOLUME = "flow_volume"
    FLOW_TIMING = "flow_timing"
    FLOW_STRUCTURE = "flow_structure"
    PROTOCOL = "protocol"
    HOST_BEHAVIOUR = "host_behaviour"
    AUTH = "auth"
    COMMAND = "command"
    DEVICE_TELEMETRY = "device_telemetry"


@dataclass(frozen=True)
class FeatureSpec:
    """One canonical feature in the contract."""

    name: str
    family: FeatureFamily
    description: str
    unit: str = ""
    # Features a dataset may legitimately lack; imputed and flagged.
    optional: bool = True
    # Non-negative count/rate features get log1p treatment.
    log_scale: bool = False


# ---------------------------------------------------------------------------
# The canonical feature contract
# ---------------------------------------------------------------------------
CANONICAL_FEATURES: tuple[FeatureSpec, ...] = (
    # -- flow volume ------------------------------------------------------
    FeatureSpec(
        "packets_per_second",
        FeatureFamily.FLOW_VOLUME,
        "Packet rate of the flow",
        "pkt/s",
        log_scale=True,
    ),
    FeatureSpec(
        "bytes_per_second",
        FeatureFamily.FLOW_VOLUME,
        "Byte rate of the flow",
        "B/s",
        log_scale=True,
    ),
    FeatureSpec("mean_packet_bytes", FeatureFamily.FLOW_VOLUME, "Mean packet size", "B"),
    FeatureSpec(
        "packets", FeatureFamily.FLOW_VOLUME, "Packet count in window", "pkt", log_scale=True
    ),
    FeatureSpec("bytes", FeatureFamily.FLOW_VOLUME, "Byte count in window", "B", log_scale=True),
    # -- flow timing ------------------------------------------------------
    FeatureSpec("flow_duration_s", FeatureFamily.FLOW_TIMING, "Flow duration", "s"),
    FeatureSpec(
        "mean_iat_ms", FeatureFamily.FLOW_TIMING, "Mean inter-arrival time", "ms", log_scale=True
    ),
    FeatureSpec(
        "iat_std_ms",
        FeatureFamily.FLOW_TIMING,
        "Inter-arrival time standard deviation",
        "ms",
        log_scale=True,
    ),
    FeatureSpec(
        "rtt_ms", FeatureFamily.FLOW_TIMING, "Round-trip latency; inflated by relaying (MITM)", "ms"
    ),
    # -- flow structure ---------------------------------------------------
    FeatureSpec(
        "syn_ratio",
        FeatureFamily.FLOW_STRUCTURE,
        "Fraction of packets with SYN set; high under flood/scan",
    ),
    FeatureSpec(
        "distinct_dst_ports",
        FeatureFamily.FLOW_STRUCTURE,
        "Distinct destination ports contacted; high under scanning",
        log_scale=True,
    ),
    FeatureSpec(
        "distinct_dst_hosts",
        FeatureFamily.FLOW_STRUCTURE,
        "Distinct destination hosts contacted",
        log_scale=True,
    ),
    FeatureSpec(
        "arp_table_changes",
        FeatureFamily.FLOW_STRUCTURE,
        "ARP table churn; high under ARP spoofing",
        log_scale=True,
    ),
    FeatureSpec(
        "duplicate_mac_observed",
        FeatureFamily.FLOW_STRUCTURE,
        "Same IP seen with conflicting MAC (binary)",
    ),
    FeatureSpec(
        "ttl_variance",
        FeatureFamily.FLOW_STRUCTURE,
        "TTL variance; extra hop from relaying inflates this",
    ),
    # -- protocol ---------------------------------------------------------
    FeatureSpec("is_tcp", FeatureFamily.PROTOCOL, "Protocol is TCP (binary)"),
    FeatureSpec("is_udp", FeatureFamily.PROTOCOL, "Protocol is UDP (binary)"),
    FeatureSpec("is_arp", FeatureFamily.PROTOCOL, "Protocol is ARP (binary)"),
    FeatureSpec("is_icmp", FeatureFamily.PROTOCOL, "Protocol is ICMP (binary)"),
    FeatureSpec(
        "dst_port_is_wellknown", FeatureFamily.PROTOCOL, "Destination port < 1024 (binary)"
    ),
    FeatureSpec(
        "dst_port_is_iomt_service",
        FeatureFamily.PROTOCOL,
        "Destination port is a known IoMT service port (binary)",
    ),
    FeatureSpec(
        "tls_downgrade", FeatureFamily.PROTOCOL, "TLS downgrade or plaintext observed (binary)"
    ),
    # -- host behaviour ---------------------------------------------------
    FeatureSpec("cpu_pct", FeatureFamily.HOST_BEHAVIOUR, "Host CPU load", "%"),
    FeatureSpec(
        "disk_write_mb_s",
        FeatureFamily.HOST_BEHAVIOUR,
        "Disk write throughput; high under mass encryption",
        "MB/s",
        log_scale=True,
    ),
    FeatureSpec("process_count", FeatureFamily.HOST_BEHAVIOUR, "Running processes"),
    FeatureSpec(
        "encrypted_file_ops",
        FeatureFamily.HOST_BEHAVIOUR,
        "Encrypted file operations in window",
        log_scale=True,
    ),
    # -- auth -------------------------------------------------------------
    FeatureSpec(
        "failed_attempts", FeatureFamily.AUTH, "Failed authentications in window", log_scale=True
    ),
    FeatureSpec("auth_succeeded", FeatureFamily.AUTH, "Authentication succeeded (binary)"),
    FeatureSpec(
        "auth_after_failures",
        FeatureFamily.AUTH,
        "Success immediately following repeated failures (binary)",
    ),
    # -- command ----------------------------------------------------------
    FeatureSpec(
        "authenticated_session",
        FeatureFamily.COMMAND,
        "Command arrived on an authenticated session (binary)",
    ),
    FeatureSpec(
        "exceeds_safe_limit",
        FeatureFamily.COMMAND,
        "Commanded setpoint outside the device safe envelope (binary)",
    ),
    FeatureSpec(
        "reduces_support", FeatureFamily.COMMAND, "Command reduces therapeutic support (binary)"
    ),
    FeatureSpec(
        "delta_setpoint_abs",
        FeatureFamily.COMMAND,
        "Absolute change in commanded setpoint",
        log_scale=True,
    ),
    FeatureSpec(
        "source_offsegment",
        FeatureFamily.COMMAND,
        "Command source outside the expected network segment (binary)",
    ),
    # -- device telemetry -------------------------------------------------
    FeatureSpec(
        "telemetry_residual",
        FeatureFamily.DEVICE_TELEMETRY,
        "Deviation of telemetry from its short-run forecast",
    ),
    FeatureSpec(
        "telemetry_variance_ratio",
        FeatureFamily.DEVICE_TELEMETRY,
        "Observed vs expected telemetry variance; spoofing is too smooth",
    ),
    FeatureSpec("alarm_active", FeatureFamily.DEVICE_TELEMETRY, "Device alarm asserted (binary)"),
    FeatureSpec(
        "missed_samples",
        FeatureFamily.DEVICE_TELEMETRY,
        "Telemetry samples missed in window",
        log_scale=True,
    ),
)

FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in CANONICAL_FEATURES)
FEATURE_BY_NAME: dict[str, FeatureSpec] = {f.name: f for f in CANONICAL_FEATURES}

FAMILY_MEMBERS: dict[FeatureFamily, tuple[str, ...]] = {
    fam: tuple(f.name for f in CANONICAL_FEATURES if f.family is fam) for fam in FeatureFamily
}

LOG_SCALE_FEATURES: tuple[str, ...] = tuple(f.name for f in CANONICAL_FEATURES if f.log_scale)

# ---------------------------------------------------------------------------
# Leakage guards
# ---------------------------------------------------------------------------
#: Columns that must NEVER reach a model. Each would leak.
FORBIDDEN_FEATURES: frozenset[str] = frozenset(
    {
        # Direct label leakage
        "ground_truth_attack",
        "ground_truth_is_attack",
        "flow_label",
        "label",
        "Label",
        "attack",
        "attack_type",
        "category",
        "Attack_type",
        # Simulator internal-truth channel: the whole point of the spoofing
        # scenario is that the *reported* signal lies, so training on truth
        # would make detection trivially and dishonestly easy.
        "truth_spo2_pct",
        "truth_heart_rate_bpm",
        "truth_minute_ventilation_l_min",
        # Identity leakage: a model keyed on device/IP memorises which asset
        # was attacked in this scenario rather than learning attack
        # behaviour, and collapses on any new fleet.
        "device_id",
        "source_ip",
        "destination_ip",
        "source_mac",
        "scenario_id",
        "event_id",
        "timestamp",
        # Trivially identifying metadata sometimes present in public sets
        "Flow ID",
        "Src IP",
        "Dst IP",
        "Timestamp",
    }
)


def assert_no_leakage(columns: list[str] | pd.Index) -> None:
    """Raise if any forbidden column is present in a training matrix.

    Called by the trainer on every fit, so leakage fails loudly rather than
    silently producing a publishable-looking 0.999 F1.
    """
    offending = sorted(set(map(str, columns)) & FORBIDDEN_FEATURES)
    if offending:
        raise ValueError(
            "Leaking columns present in the feature matrix: "
            f"{offending}. These encode the label, the simulator's internal "
            "truth channel, or asset identity, and must be dropped before "
            "fitting. See cybersecurity/schema.py:FORBIDDEN_FEATURES."
        )


# ---------------------------------------------------------------------------
# Split protocol
# ---------------------------------------------------------------------------
class SplitProtocol(StrEnum):
    """How train/test splits are formed.

    ``TEMPORAL`` and ``SCENARIO_HOLDOUT`` are the defensible choices for this
    problem. ``RANDOM`` is provided only to *demonstrate* the optimistic bias
    it introduces on sequential data, which several published IoMT results
    suffer from; it is never used for a reported headline metric.
    """

    RANDOM = "random"
    TEMPORAL = "temporal"
    SCENARIO_HOLDOUT = "scenario_holdout"
    DEVICE_HOLDOUT = "device_holdout"
    PAPER_DEFINED = "paper_defined"


@dataclass
class DatasetMeta:
    """Provenance of a dataset. Printed into every experiment report."""

    name: str
    version: str = "unknown"
    source: str = ""
    licence: str = "unknown"
    citation: str = ""
    requires_manual_download: bool = True
    local_path_hint: str = ""
    n_rows: int | None = None
    class_balance: dict[str, int] = field(default_factory=dict)
    native_split_protocol: SplitProtocol = SplitProtocol.PAPER_DEFINED
    notes: str = ""
    # Set when the dataset is the one used by a base paper we compare to.
    base_paper: str = ""
    base_paper_reported_metrics: dict[str, float] = field(default_factory=dict)


class DatasetAdapter(Protocol):
    """Interface a benchmark dataset must implement to join the pipeline.

    Implement one of these per dataset. Nothing else in the detection,
    evaluation or experiment layers needs to change.
    """

    meta: DatasetMeta

    def available(self) -> bool:
        """True if the dataset files are present locally."""
        ...

    def load(self) -> pd.DataFrame:
        """Load raw rows. May be large; implementations should chunk."""
        ...

    def to_canonical(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Map native columns onto CANONICAL_FEATURES plus a label column.

        Must return a frame whose feature columns are a subset of
        FEATURE_NAMES, plus:
          ``y_binary``     int  0 benign / 1 attack
          ``y_attack_type`` str  an :class:`AttackType` value
        Missing canonical features are left absent; the trainer imputes and
        records which were unavailable.
        """
        ...

    def label_mapping(self) -> dict[str, AttackType]:
        """Map the dataset's native class names onto our AttackType."""
        ...


__all__ = [
    "CANONICAL_FEATURES",
    "FAMILY_MEMBERS",
    "FEATURE_BY_NAME",
    "FEATURE_NAMES",
    "FORBIDDEN_FEATURES",
    "LOG_SCALE_FEATURES",
    "DatasetAdapter",
    "DatasetMeta",
    "FeatureFamily",
    "FeatureSpec",
    "SplitProtocol",
    "assert_no_leakage",
]
