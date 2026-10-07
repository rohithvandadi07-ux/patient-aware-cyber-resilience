# Dataset license and accessibility notes

Per architecture spec Section 6: datasets are selected scientifically and are not
claimed as "used" until actually downloaded and processed. This file tracks what
has and has not happened.

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
