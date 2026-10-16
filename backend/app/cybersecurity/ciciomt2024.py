"""Loader for the real CICIoMT2024 WiFi + MQTT pre-extracted flow-feature CSVs.

This is the real-data counterpart to `synthetic_data.py`. It was written
against the actual files (the `train/` and `test/` folders of the official
"WiFi and MQTT" release, 45 numeric feature columns, one CSV per attack
capture), not against guessed headers: every constant below was checked
against the real CSVs before being written down.

What the real files look like (verified, not assumed)
-----------------------------------------------------
* 50 train CSVs and 21 test CSVs. Every file has the identical 45-column header
  (see `FEATURE_COLUMNS`), all `float64`, with no missing values and no
  infinities in any file.
* There is **no label column**. The attack class is encoded only in the file
  name (`TCP_IP-DDoS-UDP3_train.pcap.csv` -> `TCP_IP-DDoS-UDP`). Several
  captures of the same attack are split over numbered files in `train/`
  (`ICMP1..ICMP8`), while `test/` has one or two files per class. This module
  strips the trailing capture number so every capture of one attack gets the
  same label.
* 19 classes: Benign, ARP_Spoofing, 2 MQTT-DDoS, 2 MQTT-DoS, MQTT-Malformed_Data,
  4 Recon, 4 TCP/IP DDoS and 4 TCP/IP DoS. This is the 19-class setup the
  L2D2 base paper (Akar et al., IEEE Access 2025) reports on.
* The official train/test split is a capture-level split, so it is kept as is
  (no random re-splitting): evaluation numbers on `test/` are comparable with
  published ones in a way a random 75/25 split of pooled rows is not.

Coarser views
-------------
`family_of` maps the 19 labels to the 6 attack families commonly used in the
dataset's own documentation (Benign, ARP spoofing, MQTT, Recon, DoS, DDoS), and
`is_attack` gives the binary view used by the patient-aware policy evaluation
(attack vs. benign). Both are derived from the 19-class label, never separately
labelled, so the three views are always mutually consistent.

Memory
------
All 45 columns are loaded as `float32` (half the footprint of the on-disk
`float64`). float32 keeps ~7 significant digits. Tree models only compare
features against thresholds, so this is expected to matter little, but its
effect on the reported metrics was not measured; it is a deliberate choice and
is recorded in the training metadata.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

import numpy as np
import pandas as pd

FEATURE_COLUMNS: list[str] = [
    "Header_Length",
    "Protocol Type",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Magnitue",  # sic -- the dataset's own spelling; kept verbatim so headers match
    "Radius",
    "Covariance",
    "Variance",
    "Weight",
]

LABEL_COLUMN = "attack_type"
SOURCE_FILE_COLUMN = "source_file"

BENIGN = "Benign"

# The 19 class names, in a fixed, documented order (also the order every
# confusion matrix in this project's reports uses).
CLASS_NAMES: list[str] = [
    "Benign",
    "ARP_Spoofing",
    "MQTT-DDoS-Connect_Flood",
    "MQTT-DDoS-Publish_Flood",
    "MQTT-DoS-Connect_Flood",
    "MQTT-DoS-Publish_Flood",
    "MQTT-Malformed_Data",
    "Recon-OS_Scan",
    "Recon-Ping_Sweep",
    "Recon-Port_Scan",
    "Recon-VulScan",
    "TCP_IP-DDoS-ICMP",
    "TCP_IP-DDoS-SYN",
    "TCP_IP-DDoS-TCP",
    "TCP_IP-DDoS-UDP",
    "TCP_IP-DoS-ICMP",
    "TCP_IP-DoS-SYN",
    "TCP_IP-DoS-TCP",
    "TCP_IP-DoS-UDP",
]

FAMILY_NAMES: list[str] = ["Benign", "ARP_Spoofing", "MQTT", "Recon", "DoS", "DDoS"]

# `<class>[<capture number>]_<split>.pcap.csv`
_FILENAME_RE = re.compile(r"^(?P<stem>.+?)(?P<num>\d*)_(?P<split>train|test)\.pcap\.csv$")


def label_from_filename(filename: str) -> str:
    """`TCP_IP-DDoS-UDP3_train.pcap.csv` -> `TCP_IP-DDoS-UDP`.

    Raises `ValueError` for a name that doesn't match the dataset's naming
    scheme or maps to a class outside the known 19, rather than silently
    inventing a label from an unexpected file.
    """
    match = _FILENAME_RE.match(Path(filename).name)
    if match is None:
        raise ValueError(f"Not a CICIoMT2024 train/test CSV name: {filename!r}")
    label = match.group("stem")
    if label not in CLASS_NAMES:
        raise ValueError(f"Unknown CICIoMT2024 class {label!r} derived from {filename!r}")
    return label


def family_of(label: str) -> str:
    """19-class label -> one of the 6 attack families."""
    if label == BENIGN:
        return "Benign"
    if label == "ARP_Spoofing":
        return "ARP_Spoofing"
    if label.startswith("MQTT-"):
        return "MQTT"
    if label.startswith("Recon-"):
        return "Recon"
    if label.startswith("TCP_IP-DDoS-"):
        return "DDoS"
    if label.startswith("TCP_IP-DoS-"):
        return "DoS"
    raise ValueError(f"Unknown CICIoMT2024 class: {label!r}")


def is_attack(label: str) -> bool:
    return label != BENIGN


def list_split_files(data_dir: Path, split: str) -> list[Path]:
    """CSV paths for one split, sorted. Accepts either the dataset root (the
    folder that contains `train/` and `test/`) or the split folder itself."""
    if split not in ("train", "test"):
        raise ValueError(f"split must be 'train' or 'test', got {split!r}")
    data_dir = Path(data_dir)
    split_dir = data_dir / split if (data_dir / split).is_dir() else data_dir
    files = sorted(split_dir.glob(f"*_{split}.pcap.csv"))
    if not files:
        raise FileNotFoundError(f"No '*_{split}.pcap.csv' files found under {split_dir}")
    return files


def cap_rows_per_class(df: pd.DataFrame, max_rows_per_class: int, seed: int = 42) -> pd.DataFrame:
    """Randomly (seeded) cap each class at `max_rows_per_class` rows, keeping
    the original row order among the survivors. Small classes are kept whole."""
    rng = np.random.default_rng(seed)
    keep: list[np.ndarray] = []
    for _, idx in df.groupby(LABEL_COLUMN, sort=False).indices.items():
        if len(idx) > max_rows_per_class:
            idx = rng.choice(idx, size=max_rows_per_class, replace=False)
        keep.append(np.sort(idx))
    return df.iloc[np.concatenate(keep)].reset_index(drop=True)


def split_train_validation(
    df: pd.DataFrame, val_fraction: float = 0.2, gap_fraction: float = 0.01
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, dict[str, object]]]:
    """Split the TRAIN split into train and validation without random row
    shuffling (adjacent flows of one capture are near-duplicates, so a random
    split would leak).

    * A class with two or more capture files: the last file (by name) is held
      out whole -- a capture-level split, as strict as the official one.
    * A class with ONE capture file (Benign and ARP_Spoofing are both like
      this): the final `val_fraction` of its rows, in file order, is held out as
      a contiguous block, with the `gap_fraction` of rows just before it dropped
      so the nearest training and validation flows are not neighbours. This is
      weaker than a capture-level split (same capture, same session), so
      validation numbers for those classes are expected to be optimistic.

    `df` must be an uncapped `load_split` result (rows in file order). Returns
    (train, validation, per-class description of how each class was split).
    """
    if not 0.0 < val_fraction < 0.5:
        raise ValueError("val_fraction must be in (0, 0.5)")
    train_idx: list[np.ndarray] = []
    val_idx: list[np.ndarray] = []
    info: dict[str, dict[str, object]] = {}
    source = df[SOURCE_FILE_COLUMN].to_numpy()
    for label, idx in df.groupby(LABEL_COLUMN, sort=False).indices.items():
        files = list(dict.fromkeys(source[idx]))
        if len(files) >= 2:
            held = sorted(files)[-1]
            is_val = source[idx] == held
            train_idx.append(idx[~is_val])
            val_idx.append(idx[is_val])
            info[label] = {"method": "held-out capture", "validation_capture": held, "dropped_gap_rows": 0}
        else:
            n = len(idx)
            start = int(n * (1.0 - val_fraction))
            gap = int(n * gap_fraction)
            train_idx.append(idx[: start - gap])
            val_idx.append(idx[start:])
            info[label] = {
                "method": "single capture: contiguous tail block",
                "validation_capture": files[0],
                "dropped_gap_rows": gap,
            }
    train = df.iloc[np.sort(np.concatenate(train_idx))].reset_index(drop=True)
    val = df.iloc[np.sort(np.concatenate(val_idx))].reset_index(drop=True)
    return train, val, info


def load_split(
    data_dir: Path,
    split: str,
    *,
    max_rows_per_class: int | None = None,
    seed: int = 42,
    files: Iterable[Path] | None = None,
) -> pd.DataFrame:
    """Load every CSV of one split into one DataFrame (float32 features plus a
    `attack_type` label and a `source_file` provenance column).

    `max_rows_per_class` randomly (seeded) caps each class at that many rows
    *after* pooling all of that class's captures -- a documented training-time
    option for the classes that have millions of near-identical flood rows. It
    must never be used on the evaluation split; the training script only
    applies it to `train`.
    """
    paths = list(files) if files is not None else list_split_files(data_dir, split)

    frames: list[pd.DataFrame] = []
    for path in paths:
        label = label_from_filename(path.name)
        frame = pd.read_csv(path, dtype=np.float32)
        missing = [c for c in FEATURE_COLUMNS if c not in frame.columns]
        if missing:
            raise ValueError(f"{path.name} is missing expected feature columns: {missing}")
        frame = frame[FEATURE_COLUMNS]
        frame[LABEL_COLUMN] = label
        frame[SOURCE_FILE_COLUMN] = path.name
        frames.append(frame)

    df = pd.concat(frames, ignore_index=True)

    if max_rows_per_class is not None:
        df = cap_rows_per_class(df, max_rows_per_class, seed)

    return df


def class_counts(df: pd.DataFrame) -> dict[str, int]:
    """Row count per class, in `CLASS_NAMES` order (classes absent from `df`
    are reported as 0, never silently dropped)."""
    counts = df[LABEL_COLUMN].value_counts()
    return {name: int(counts.get(name, 0)) for name in CLASS_NAMES}
