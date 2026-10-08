# Datasets

## Decision

**Primary benchmark: CICIoMT2024** (Wi-Fi + MQTT subset).
**Secondary / optional: IoMT-TrafficData**, WUSTL-EHMS 2020.
**Closed-loop evaluation: the project's own IoMT simulator** (Track B).

Rationale, licensing, schema and ingestion are below. The split between
"benchmark detection" and "simulator closed-loop" evaluation is explained in
[`related-work.md`](related-work.md#3-comparison-strategy).

---

## 1. CICIoMT2024 — primary benchmark

**Citation**

> S. Dadkhah, E. C. P. Neto, R. Ferreira, R. C. Molokwu, S. Sadeghi and
> A. A. Ghorbani, "CICIoMT2024: Attack Vectors in Healthcare devices — A
> Multi-Protocol Dataset for Assessing IoMT Device Security," *Internet of
> Things*, vol. 28, December 2024.

**Source** — Canadian Institute for Cybersecurity, University of New Brunswick
<https://www.unb.ca/cic/datasets/iomt-dataset-2024.html>
Download: <http://cicresearch.ca/IOTDataset/CICIoMT2024/>

**Why this one**

- IoMT-specific rather than generic IoT: captured from **40 medical devices
  (25 real, 15 simulated)**, so device behaviour is representative of the
  domain we defend.
- **Multi-protocol**: Wi-Fi, MQTT and BLE. MQTT matters because it is the
  dominant IoMT telemetry transport and is the transport our simulator models.
- **Current** (Dec 2024) with an active 2025–26 comparison literature, so
  published baselines exist for a comparison table.
- Ships **pre-extracted CSV features** alongside raw pcaps, with an official
  train/test split, which removes a major source of
  incomparability between papers.

**Licensing / access**

- No explicit licence is published on the dataset page; the page carries a
  University of New Brunswick copyright notice. **Citation of the dataset
  paper is required.** Treat as research-use, cite-on-use.
- Requires **manual download** — it is not fetched automatically by any code
  in this repository, and no dataset files are committed
  (see `.gitignore`). A Kaggle mirror exists
  (`limamateus/cic-iomt-2024-wifi-mqtt`); prefer the official CIC source.

### Attack taxonomy

The dataset supports three classification tasks, which the comparison
literature uses consistently:

| Task | Classes |
|---|---|
| **Binary** | Benign, Attack |
| **6-class** | Benign, DDoS, DoS, Recon, MQTT, ARP Spoofing |
| **19-class** | Benign + 18 attack subtypes |

19-class breakdown:

- **TCP/IP DDoS** — SYN, TCP, ICMP, UDP floods
- **TCP/IP DoS** — SYN, TCP, ICMP, UDP floods
- **Recon** — Ping Sweep, OS Scan, Port Scan, Vulnerability Scan
- **MQTT** — Malformed Data, DoS Connect Flood, DDoS Connect Flood,
  DoS Publish Flood, DDoS Publish Flood
- **Spoofing** — ARP Spoofing
- *(BLE DoS is present in the Bluetooth subset, excluded from the Wi-Fi/MQTT
  task set)*

### Feature schema

The Wi-Fi/MQTT CSVs carry ~45 extracted flow features:

```
Header_Length, Protocol Type, Duration, Rate, Srate, Drate,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
ack_flag_number, ece_flag_number, cwr_flag_number,
ack_count, syn_count, fin_count, rst_count,
HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP,
IGMP, IPv, LLC,
Tot sum, Min, Max, AVG, Std, Tot size, IAT, Number, Magnitue, Radius,
Covariance, Variance, Weight
```

Note `Magnitue` is misspelled in the source data; adapters must match the
source spelling exactly.

**Mapping to our canonical schema.** These columns map onto
`cybersecurity/schema.py:CANONICAL_FEATURES` as follows (families in
parentheses):

| CICIoMT2024 | Canonical | Family |
|---|---|---|
| `Rate`, `Srate` | `packets_per_second` | flow_volume |
| `Tot size`, `AVG` | `mean_packet_bytes` | flow_volume |
| `Tot sum` | `bytes` | flow_volume |
| `Number` | `packets` | flow_volume |
| `Duration` | `flow_duration_s` | flow_timing |
| `IAT` | `mean_iat_ms` | flow_timing |
| `Std`, `Variance` | `iat_std_ms` | flow_timing |
| `syn_flag_number`, `syn_count` | `syn_ratio` | flow_structure |
| `ARP` | `is_arp`, `arp_table_changes` | protocol / flow_structure |
| `TCP`, `UDP`, `ICMP` | `is_tcp`, `is_udp`, `is_icmp` | protocol |
| `Header_Length` | *(retained as dataset-native)* | — |

Canonical features with **no CICIoMT2024 counterpart** — all host-behaviour,
auth, command and device-telemetry families, plus `rtt_ms`, `ttl_variance`,
`duplicate_mac_observed` — are recorded as unavailable by the trainer and
imputed. This is reported in experiment output, because it means
CICIoMT2024 can only exercise the **network-borne** portion of our threat
model. The host- and command-level threats (malicious command injection,
telemetry spoofing, ransomware behaviour) are evaluated on the simulator,
and the paper must state this division.

### Published baselines (comparison targets)

Reported by *"Comprehensive Feature Selection for Machine Learning-Based
Intrusion Detection"*, SCITEPRESS 2025
(<https://www.scitepress.org/Papers/2025/133136/133136.pdf>) —
XGBoost with top-15 Information-Gain features, 80/20 split, balanced
sampling (5,000/class binary):

| Task | Accuracy | Notes |
|---|---|---|
| Binary | 0.997 | Attack F1 0.997 / Benign F1 0.997 |
| 6-class | 0.977 | Weakest class: ARP Spoofing (F1 0.942) |
| 19-class | 0.967 | Weakest class: Recon-OS Scan (F1 0.850) |

Also reported: Decision Tree, Random Forest, KNN (figures only, no numeric
table); feature selection via Fisher Score, Mutual Information and
Information Gain, with Pearson pre-filtering at |r| > 0.80 reducing 44
features to 36; 3–4 features sufficient for binary, 7–8 for most multi-class
tasks. No random seed, stratification or cross-validation stated — so our
reproduction fixes and reports all three.

> **Observation for the paper.** Binary detection on CICIoMT2024 is close to
> saturated (F1 > 0.99 with <5 features, multiple independent papers). We
> therefore do **not** position detection accuracy as a contribution. We
> report it to show the detector is sound, then direct the contribution at
> the decision layer. Competing for a fourth decimal place on a saturated
> benchmark would be a weak paper; identifying what to do *after* detection
> is not.

### Known pitfalls we must avoid

Documented so the implementation guards against each:

1. **Flow-level random splitting leaks.** Packets from one flow land in both
   train and test, inflating scores. We use the dataset's **official
   train/test split** and additionally report a temporal split.
2. **Identity features leak.** IP/MAC/port identity lets a model memorise
   which host was attacked. Guarded by
   `cybersecurity/schema.py:FORBIDDEN_FEATURES`, enforced on every fit.
3. **Balanced-sampling optimism.** Papers reporting on balanced subsets
   (5,000/class) overstate deployed performance under real imbalance. We
   report **both** balanced (for comparability with published numbers) and
   natural-prevalence results, and treat the latter as the honest figure.
4. **Accuracy on imbalanced data is uninformative.** Headline metrics are
   macro-F1 and PR-AUC; accuracy is reported only for comparability.

---

## 2. IoMT-TrafficData — secondary

9-class task: Apachekiller, ARP Spoofing, Camoverflow, MQTT-Malaria,
Netscan, Normal, RUDeadYet, Slowloris, Slowread. 21 features (20 after
dropping the binary label). Published XGBoost reference: binary 0.997,
9-class 0.987 (same SCITEPRESS 2025 source).

**Use:** cross-dataset generalisation. A detector tuned on CICIoMT2024 and
evaluated here tests whether performance transfers — a question the
systematic reviews specifically flag as under-examined.

## 3. WUSTL-EHMS 2020 — optional

Enhanced Healthcare Monitoring System testbed. Notable because it combines
**network flow features with patient biometric features**, which is the only
public dataset that approaches our clinical-context requirement.

**Use if time permits:** it is the closest public analogue to our clinical
coupling, so it strengthens the claim that patient context is obtainable in
principle. It is small and spoofing/data-injection focused, so it does not
replace CICIoMT2024 as the detection benchmark.

## 4. Datasets considered and not selected

| Dataset | Reason not primary |
|---|---|
| ECU-IoHT | Small; limited attack diversity; little recent comparison literature |
| WUSTL-HDRL-2024 | Reinforcement-learning oriented; mismatched to our supervised detection task |
| NF-BoT-IoT | Generic IoT, not medical devices; no clinical relevance |
| TON_IoT, CICIDS2017, NSL-KDD | Not IoMT; included only if a reviewer asks for generic-IDS context |

---

## 5. Ingestion procedure

No dataset file is committed to this repository, and no code downloads one
automatically.

```bash
# 1. Obtain the dataset manually, honouring its terms, then place it at:
#    datasets/raw/ciciomt2024/WiFi_and_MQTT/attacks/csv/{train,test}/*.csv

# 2. Verify presence, schema and class balance
python -m cybersecurity.datasets.cli verify --dataset ciciomt2024

# 3. Convert to the canonical schema (writes datasets/processed/)
python -m cybersecurity.datasets.cli prepare --dataset ciciomt2024

# 4. Train and evaluate against the official split
python -m experiments.runners.detection_benchmark --dataset ciciomt2024 \
       --task binary --split official --seed 20260101
```

Every run writes a manifest recording dataset name, file checksums, row
counts, class balance, split protocol, seed, feature availability and library
versions, so that any reported number is traceable to the exact inputs that
produced it (see [`reproducibility.md`](reproducibility.md)).

### If the dataset is absent

Benchmark experiments **skip with an explicit message** and the metrics are
recorded as unavailable. They are never substituted with simulator numbers,
and no placeholder values are written. Tests covering benchmark paths are
marked `requires_dataset` and skip cleanly.
