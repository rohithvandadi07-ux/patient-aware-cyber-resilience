# Dataset license and accessibility notes

Per architecture spec Section 6: datasets are selected scientifically and are not
claimed as "used" until actually downloaded and processed. This file tracks what
has and has not happened.

## Base paper for journal comparison (post-Phase-15, user-directed)

Darshan asked for a strong IEEE-or-Elsevier 2025 base paper, with the dataset
taken *from that paper* so a journal write-up can report a real, same-dataset
comparison. The first candidate checked for this project did not actually
satisfy that — recorded here so the correction is traceable, not silently
swapped.

- **Rejected as base paper:** Zachos, Mantas, Porfyrakis, Sobral de Bastos &
  Rodriguez, "Anomaly-based intrusion detection for IoMT networks: design,
  implementation, dataset generation, and ML algorithms evaluation," *IEEE
  Access*, vol. 13, pp. 41994-42028, 2025, DOI 10.1109/ACCESS.2025.3547572.
  Verified (via the authors' own institutional repository, gala.gre.ac.uk)
  that this paper generates its **own, unreleased** dataset on a Raspberry-Pi
  IoT/IoMT testbed for unsupervised novelty/outlier detection (OCSVM, LOF,
  G_KDE, PW_KDE, B_GMM, MCD, IsoForest) — no CICIoMT2024, no public dataset
  DOI, nothing we could actually obtain or reuse. It was originally paired in
  this project's own notes with the unrelated CORA.RDR/Dataverse release
  below purely because their taxonomies happened to look compatible — that
  pairing did not mean the two shared a dataset, and would not have supported
  a real same-dataset comparison. Kept only as a related-work citation on
  resource-constrained AIDS design, not as the dataset anchor.
- **Adopted base paper:** Akar, Sahmoud, Onat, Çavuşoğlu & Malondo, "L2D2: A
  Novel LSTM Model for Multi-Class Intrusion Detection Systems in the Era of
  IoMT," *IEEE Access*, vol. 13, pp. 7002-7013, 2025, DOI
  10.1109/ACCESS.2025.3526883 (ISSN 2169-3536). Verified (via Fatih Sultan
  Mehmet Vakıf Üniversitesi's institutional repository) to train and evaluate
  an LSTM directly on **CICIoMT2024** — 19 classes, 98% reported accuracy.
  This is the same dataset CICIoMT2024 names below, so getting the raw
  CICIoMT2024 CSVs (via `download_ciciomt2024.py`) gives a literal
  same-dataset comparison against this paper's own reported numbers, not an
  approximate one.
- **Why this also answers the "novelty" question, not just the dataset
  question:** every 2025/2024 paper found in this search that actually
  trains on CICIoMT2024 or a comparable IoMT dataset — this one, Shaikh et
  al.'s HCLR-IDS (Frontiers in Medicine, 2025, DOI 10.3389/fmed.2025.1524286,
  binary 99.58% / 18-class 77.73% accuracy on CICIoMT2024), and Balhareth &
  Ilyas's tree-based IDS (Sensors, 2024, DOI 10.3390/s24175712, on
  CICIDS2017, not even IoMT-specific) — stops at classifying the attack.
  None of them decide what to *do* about a detected attack in a way that
  weighs clinical/patient impact; Shaikh et al.'s own introduction raises
  "patient safety" only as motivation, never as something the system
  measures or acts on. That is this project's actual, defensible novelty
  claim for a journal submission: a patient-aware *decision* layer (dual-risk
  model + policy engine + multi-agent reasoning + verified recovery +
  immutable blockchain audit) sitting downstream of detection — not a
  claim of a better detector than L2D2's 98%. The existing ablation study
  (`evaluation/phase13_baseline_comparison.md`, 0/162 vs. 162/162
  unsafe-autonomous-action rate) is already the right shape of evidence for
  this claim; it just needs the real CICIoMT2024 data substituted for the
  synthetic stand-in to be publishable as-is.
- **A faster-to-use alternative, not the same thing:** a real, open
  (CC-BY-4.0), ML-ready unified release of CICIoMT2024 + IoMT-TrafficData
  exists on CORA.RDR/Dataverse (DOI 10.34810/DATA3305, creators Petrakis,
  Doménech Fons, Leon, Martin-Faus & Pegueroles — unrelated to either paper
  above), 8,011,534 rows, 58 window-level features via their own
  "MIOTTA-NPT" extraction, with both a 6-class taxonomy
  (Benign/DDoS/DoS/MQTT/Reconnaissance/Spoofing — matching this project's
  `AttackCategory` enum) and a 26-subtype fine-grained one. It is easier to
  get (one DOI, no CIC terms-of-use click-through) and already tabular, but
  its re-extraction is not guaranteed to reproduce CICIoMT2024's original
  CSV features exactly — so it's a fine choice if the goal is just "a real,
  open, correctly-labeled IoMT dataset," but the *exact* same-dataset
  comparison against the Akar et al. 98%/19-class number specifically needs
  the original CICIoMT2024 CSVs below, not this derived table.

## CICIoMT2024 (primary detection dataset)

- **Source:** Canadian Institute for Cybersecurity (CIC), University of New
  Brunswick — https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
- **License:** CIC datasets are released for research use; CIC's standard terms
  require citing the originating paper and do not permit redistribution of the
  raw dataset itself. Review the exact terms on the page above before
  downloading — do not rely on this note as a substitute for reading them.
- **Access status as of this commit: NOT YET DOWNLOADED.** The sandboxed
  development environment this project is being built in has network egress
  restricted to a small allowlist (package registries) and cannot reach
  `unb.ca` or the CIC research mirror. `download_ciciomt2024.py` in this
  directory is written to run correctly on a machine that *does* have internet
  access (e.g. your own laptop) — it has not been run yet, and no performance
  number anywhere in this repository is based on real CICIoMT2024 data.
- **What stands in for it until then:** `app/cybersecurity/synthetic_data.py`
  generates a synthetic dataset with the same feature schema and attack-category
  labels as CICIoMT2024's extracted flow-feature CSVs (see that module's
  docstring for the exact feature list and how it was derived from the dataset's
  published documentation). This lets the training pipeline, model code, and
  evaluation harness be built and tested now. Every report generated from
  synthetic data says so explicitly — see `experiments/README.md`.

## WUSTL-EHMS-2020 (secondary, network+clinical fusion dataset)

- **Source:** Washington University in St. Louis —
  https://www.cse.wustl.edu/~jain/ehms/index.html
- **License:** Available for academic research use; check the page for exact
  terms before downloading.
- **Access status: NOT YET DOWNLOADED.** Same network restriction as above.
  Deferred until CICIoMT2024 baselines are working, per the architecture spec's
  phased approach — WUSTL-EHMS-2020 is the secondary dataset, not the one Phase
  3's first baseline depends on.

## ECU-IoHT

- Deferred per architecture spec Section 3 — not disqualified, just not needed
  for the current baseline. Not downloaded, not evaluated, no notes yet beyond
  what's already in the architecture doc.

## How to actually get CICIoMT2024 onto this project

1. On a machine with normal internet access, clone/pull this repository (or just
   copy `datasets/download_ciciomt2024.py`).
2. Read the license terms on the CIC page above and confirm you accept them.
3. Run `python datasets/download_ciciomt2024.py --output datasets/raw/ciciomt2024/`
   (see that script's `--help` for options).
4. Copy the resulting `datasets/raw/ciciomt2024/` directory into this project's
   working copy — it's gitignored, so it won't accidentally get committed.
5. Point `app/cybersecurity/training.py` at the real CSVs instead of
   `synthetic_data.py` (the training script's `--data-dir` flag) and re-run.
6. Update this file's "Access status" line and `experiments/` results to say the
   real dataset was used, with the date and CICIoMT2024's version/release you
   downloaded.
