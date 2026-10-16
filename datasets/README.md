# datasets

Dataset download scripts and license/accessibility notes for CICIoMT2024 (primary)
and WUSTL-EHMS-2020 (secondary, network+clinical fusion). Raw dataset files
themselves are gitignored — never committed to the repository.

## Status

- **CICIoMT2024 (WiFi + MQTT release): in use.** The official pre-extracted CSVs
  (`train/` 50 files, `test/` 21 files, 45 numeric flow features, no label
  column — the class is encoded in the file name) were downloaded by hand and
  are loaded by `backend/app/cybersecurity/ciciomt2024.py`. Point the training
  script at the folder that contains `train/` and `test/`:

  ```
  cd backend
  python -m app.cybersecurity.train_ciciomt2024 --data-dir /path/to/iomt
  ```

  Results: `evaluation/ciciomt2024_results.md`.
- **WUSTL-EHMS-2020: not downloaded or used yet.**
- **Synthetic stand-in** (`backend/app/cybersecurity/synthetic_data.py`) is still
  what the runtime detector and the Phase 13 ablation harness train on, because
  they depend on a 15-feature schema the simulator can produce.
