"""Synthetic stand-in for CICIoMT2024, shaped like its real feature schema.

IMPORTANT: this module generates SYNTHETIC data. It does not contain, derive
from, or approximate any real CICIoMT2024 sample. It exists only because this
project's development environment cannot reach CIC's servers to download the
real dataset (see datasets/LICENSE_NOTES.md) -- it lets the training pipeline,
model code, and evaluation harness get built and tested now, with the real
dataset swapped in later via `--data-dir` once it's actually downloaded.

Every function and report that uses this module says "synthetic" explicitly.
No metric produced from this data is ever reported as a CICIoMT2024 benchmark
number -- see `app/cybersecurity/training.py`'s README note and
`experiments/README.md`.

Feature schema: CICIoMT2024's published pre-extracted CSVs use flow-level
features in the same family as CIC's other NetFlow-based IDS datasets
(CICIDS2017, CICIoT2023) -- packet/byte counts, flow duration, inter-arrival
time statistics, and TCP flag counts, per flow. The exact per-column names were
not independently confirmed from a real downloaded CSV (not accessible from
this environment), so the fields below are a representative, clearly-labeled
subset of that *feature family*, not a verified transcription of CIC's literal
column headers. Treat `FEATURE_COLUMNS` as "what a flow-feature dataset in this
family generally looks like," and reconcile it against the real column headers
the moment the actual CICIoMT2024 CSVs are downloaded.
"""

import random

import pandas as pd

from app.schemas.enums import AttackCategory

FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packet_rate",
    "byte_rate",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "protocol_tcp",
    "protocol_udp",
    "protocol_mqtt",
]

LABEL_COLUMN = "attack_type"

# Per-class generation parameters: (mean, std) per feature, roughly reflecting
# the qualitative shape described in the architecture spec (e.g. flood attacks
# have very high packet_rate and syn_flag_count; benign traffic is lower and
# more varied). These are illustrative, not measured -- see module docstring.
_CLASS_PROFILES: dict[AttackCategory, dict[str, tuple[float, float]]] = {
    AttackCategory.UNKNOWN: {  # used here as the synthetic "benign" class
        "flow_duration": (2.0, 1.5),
        "total_fwd_packets": (20, 10),
        "total_bwd_packets": (18, 9),
        "total_fwd_bytes": (2000, 800),
        "total_bwd_bytes": (1800, 700),
        "packet_rate": (10, 5),
        "byte_rate": (1000, 400),
        "fwd_iat_mean": (0.1, 0.05),
        "bwd_iat_mean": (0.1, 0.05),
        "syn_flag_count": (1, 0.5),
        "ack_flag_count": (15, 5),
        "rst_flag_count": (0.1, 0.2),
    },
    AttackCategory.DOS: {
        "flow_duration": (0.5, 0.3),
        "total_fwd_packets": (500, 150),
        "total_bwd_packets": (2, 2),
        "total_fwd_bytes": (30000, 8000),
        "total_bwd_bytes": (100, 100),
        "packet_rate": (800, 200),
        "byte_rate": (40000, 10000),
        "fwd_iat_mean": (0.001, 0.001),
        "bwd_iat_mean": (0.5, 0.5),
        "syn_flag_count": (400, 100),
        "ack_flag_count": (5, 3),
        "rst_flag_count": (2, 2),
    },
    AttackCategory.DDOS: {
        "flow_duration": (0.3, 0.2),
        "total_fwd_packets": (1200, 300),
        "total_bwd_packets": (1, 1),
        "total_fwd_bytes": (70000, 15000),
        "total_bwd_bytes": (50, 50),
        "packet_rate": (2000, 400),
        "byte_rate": (90000, 15000),
        "fwd_iat_mean": (0.0005, 0.0005),
        "bwd_iat_mean": (0.8, 0.5),
        "syn_flag_count": (1000, 250),
        "ack_flag_count": (3, 2),
        "rst_flag_count": (5, 3),
    },
    AttackCategory.RECONNAISSANCE: {
        "flow_duration": (0.2, 0.15),
        "total_fwd_packets": (3, 2),
        "total_bwd_packets": (1, 1),
        "total_fwd_bytes": (150, 80),
        "total_bwd_bytes": (40, 40),
        "packet_rate": (15, 8),
        "byte_rate": (700, 300),
        "fwd_iat_mean": (0.05, 0.03),
        "bwd_iat_mean": (0.2, 0.2),
        "syn_flag_count": (2, 1),
        "ack_flag_count": (1, 1),
        "rst_flag_count": (1.5, 1),
    },
    AttackCategory.MQTT_BASED: {
        "flow_duration": (1.0, 0.6),
        "total_fwd_packets": (200, 60),
        "total_bwd_packets": (180, 50),
        "total_fwd_bytes": (15000, 4000),
        "total_bwd_bytes": (14000, 3800),
        "packet_rate": (300, 80),
        "byte_rate": (18000, 4000),
        "fwd_iat_mean": (0.01, 0.005),
        "bwd_iat_mean": (0.01, 0.005),
        "syn_flag_count": (1, 0.5),
        "ack_flag_count": (190, 50),
        "rst_flag_count": (0.1, 0.1),
    },
    AttackCategory.SPOOFING: {
        "flow_duration": (0.4, 0.3),
        "total_fwd_packets": (30, 15),
        "total_bwd_packets": (28, 14),
        "total_fwd_bytes": (2500, 1000),
        "total_bwd_bytes": (2400, 1000),
        "packet_rate": (60, 25),
        "byte_rate": (4500, 1800),
        "fwd_iat_mean": (0.03, 0.02),
        "bwd_iat_mean": (0.03, 0.02),
        "syn_flag_count": (2, 1),
        "ack_flag_count": (25, 10),
        "rst_flag_count": (0.5, 0.5),
    },
}

_PROTOCOL_BY_CLASS: dict[AttackCategory, str] = {
    AttackCategory.UNKNOWN: "tcp",
    AttackCategory.DOS: "tcp",
    AttackCategory.DDOS: "udp",
    AttackCategory.RECONNAISSANCE: "tcp",
    AttackCategory.MQTT_BASED: "mqtt",
    AttackCategory.SPOOFING: "tcp",
}


def _sample_row(rng: random.Random, attack_type: AttackCategory) -> dict[str, float]:
    profile = _CLASS_PROFILES[attack_type]
    row = {
        feature: max(0.0, rng.gauss(mean, std))
        for feature, (mean, std) in profile.items()
    }

    protocol = _PROTOCOL_BY_CLASS[attack_type]
    row["protocol_tcp"] = 1.0 if protocol == "tcp" else 0.0
    row["protocol_udp"] = 1.0 if protocol == "udp" else 0.0
    row["protocol_mqtt"] = 1.0 if protocol == "mqtt" else 0.0

    return row


def generate_synthetic_dataset(
    seed: int = 42,
    samples_per_class: dict[AttackCategory, int] | None = None,
) -> pd.DataFrame:
    """Generate a synthetic, labeled flow-feature dataset.

    Default class sizes deliberately mimic CICIoMT2024's documented class
    imbalance (benign + a flood-type class dominate; reconnaissance and
    spoofing are comparatively rare) -- architecture spec Section 10 requires
    handling that imbalance as a visible, documented experimental step, which
    means the synthetic data needs to actually exhibit it, not be artificially
    balanced.
    """
    if samples_per_class is None:
        samples_per_class = {
            AttackCategory.UNKNOWN: 4000,
            AttackCategory.DOS: 1500,
            AttackCategory.DDOS: 1200,
            AttackCategory.RECONNAISSANCE: 300,
            AttackCategory.MQTT_BASED: 900,
            AttackCategory.SPOOFING: 250,
        }

    rng = random.Random(seed)
    rows: list[dict[str, float | str]] = []

    for attack_type, count in samples_per_class.items():
        for _ in range(count):
            row = _sample_row(rng, attack_type)
            row[LABEL_COLUMN] = attack_type.value
            rows.append(row)

    df = pd.DataFrame(rows)
    # Shuffle so class order isn't trivially learnable from row position.
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
