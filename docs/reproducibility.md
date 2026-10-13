# Reproducibility guide

How to re-run this project's deterministic scenarios and evaluation, what
will come back identical, and what is honestly expected to vary — based on
reading the actual seeded code paths, not an assumption that "seeded"
implies "every number is pinned."

## 1. Environment setup

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

Python version used when this was last verified: 3.13.16 (the venv's own
`.venv/bin/python3`); `backend/pyproject.toml` targets `py312` for `ruff`,
so 3.12+ is the supported floor, not a strict pin. No `backend/
requirements.txt` entry pins an exact Python interpreter version.

For the frontend test suite: `cd frontend && npm install` (Node 22, per
`frontend/Dockerfile`'s `node:22-alpine` base — not independently pinned
via `.nvmrc` in this repo, so match that version if you need bit-for-bit
toolchain reproducibility).

## 2. What is actually deterministic, and why

### The IoMT simulator / `ScenarioRunner`

`backend/app/iomt_simulator/scenario.py`'s `ScenarioRunner` takes a `seed:
int` and constructs one `random.Random(seed)` instance, shared across every
device's telemetry generation for that run. Per its own docstring: "pass
the same `seed` and the same `injections` and the `telemetry` and
`network_events` lists in the returned `ScenarioResult` will be identical,
call for call, run for run." This is exercised directly by
`/detections/run-scenario`, which always uses `seed=42` and the same fixed
`AttackInjection` (ventilator-01, spoofed `set_tidal_volume`, tick 6) —
calling that endpoint twice, in two different processes, produces the exact
same `telemetry`/`network_events` lists.

To reproduce a scenario run yourself:

```python
from app.iomt_simulator.hospital import build_default_fleet
from app.iomt_simulator.scenario import AttackInjection, ScenarioRunner

registry = build_default_fleet()
injection = AttackInjection(
    tick=6, device_id="ventilator-01", event_type="spoofed_command",
    payload={"command": "set_tidal_volume", "value": "50"},
    device_effect=lambda d: d.set_network_state("compromised"),
)
result = ScenarioRunner(registry, seed=42, injections=[injection]).run(num_ticks=10)
# result.telemetry / result.network_events are identical every time
```

### Model training (`backend/app/cybersecurity/training.py`)

```bash
cd backend && source .venv/bin/activate
python -m app.cybersecurity.training --seed 42
```

`train_baselines(df, seed=42)` by default: the seed is passed to
`train_test_split`'s `random_state` and to both `RandomForestClassifier`
and `XGBClassifier`'s own `random_state`. Given the same synthetic dataset
(itself seeded — see below) and the same scikit-learn/XGBoost versions
pinned in `backend/requirements.txt`, the train/test split and both models'
learned parameters should be identical run to run on the same machine
architecture.

**What can still vary even with the same seed:** floating-point
non-associativity across different BLAS/CPU architectures, and any
non-determinism XGBoost's own histogram-building introduces under
multi-threading (not independently verified bit-for-bit across machines in
this project — treated as a known caveat, not confirmed safe). Expect the
same seed to be reproducible on the *same* machine/environment reliably;
treat cross-machine bit-for-bit reproduction as unverified.

### The synthetic dataset itself

`backend/app/cybersecurity/synthetic_data.py`'s `generate_synthetic_dataset`
takes its own `seed` (the training script's `--seed`, default 42, is reused
here — `training.py`'s `main()` calls `generate_synthetic_dataset(seed=
args.seed)`). Given the same seed, the generated rows (feature values and
labels) are identical run to run — it's a pure Python `random.Random(seed)`
generator, not drawing from system entropy or wall-clock time.

### The baseline comparison (`run_baseline_comparison.py`)

```bash
cd backend && source .venv/bin/activate
python -m app.evaluation.run_baseline_comparison
```

Two independent seeds are hard-coded in this script, deliberately kept
separate (`run_baseline_comparison.py`'s own module-level constants):

- `_TRAINING_SEED = 42` — same default as `training.py`, used to generate
  and split the synthetic dataset fresh for this run.
- `_DEVICE_CONTEXT_SEED = 2026` — independent, because (per
  `baseline_systems.sample_device_contexts`'s own docstring) device context
  must not be correlated with which row of the dataset it's paired with.

Given these two fixed seeds and the same package versions, re-running this
script should reproduce: the same train/test split, the same trained
model, the same sampled device contexts, and therefore the same per-trial
decisions and the same aggregate rates (`unsafe_autonomous_action_rate`,
`unnecessary_isolation_rate`, counts) reported in
`evaluation/phase13_baseline_comparison.json`/`.md`. This is not a claim
this exact reproduction was re-verified bit-for-bit as part of writing this
guide — rerun it yourself and diff against the committed report if you
need that confirmed.

### What is *not* seeded, and will vary run to run

- **`generated_at` / any timestamp field** — always the real wall-clock
  time of the run, by design (so a report's provenance is honest about
  when it was produced).
- **`uuid4()`-derived incident IDs** (e.g. `/detections/run-scenario`'s
  `INC-{device_id}-{uuid4().hex[:8]}`) — random every call; this affects
  only the *label*, never the underlying detection/telemetry content.
- **Any real LLM call** — moot today, since no real `LLMClient`
  implementation exists anywhere in this codebase (`MockLLMClient` returns
  fixed, scripted responses, which *are* deterministic, but that
  determinism is an artifact of using a mock, not evidence that a real
  model would reproduce the same output).
- **Wall-clock-dependent test assertions**, if any exist — none were found
  in a review of the seeded paths above, but this guide does not claim to
  have audited every test file for a hidden `datetime.now()`.

## 3. Re-running the test suites (what "passing" means, concretely)

```bash
# Backend
cd backend && source .venv/bin/activate
pytest                     # 366 tests collected as of this writing
ruff check app

# Frontend
cd frontend
npm run test
npm run lint
npm run build

# End-to-end (Playwright, real Chromium)
cd backend && source .venv/bin/activate
playwright install chromium   # once
pytest -c ../tests/pytest.ini ../tests/e2e

# Dependency/vulnerability scans (point-in-time, not deterministic content
# — results depend on the CVE database's state when run)
pip-audit
cd frontend && npm audit
cd blockchain/chaincode && npm audit
```

Exact counts reported in this repo's own docs drift phase to phase (342 →
359 → 366 as this project grew, and the Postgres-migration phase's own
README notes 356 vs. an earlier "359" was "an approximation, not a
regression") — treat the exact number as a point-in-time fact to re-verify
with `pytest --collect-only -q`, not a fixed target to match exactly.

## 4. Postgres-backed test path (optional, needs a real Postgres)

`backend/tests/test_postgres_repositories.py` (7 tests) is **skipped**,
not faked, when no Postgres is reachable at `DATABASE_URL` — this is the
correct, honest behavior, not a gap. To actually run it:

```bash
# Install/start Postgres 16 natively (see docs/deployment.md §2)
cd backend && source .venv/bin/activate
export REPOSITORY_BACKEND=postgres
export DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/patient_aware_cyber_resilience
pytest tests/test_postgres_repositories.py -v
```

## 5. What would need to change for a true third-party reproduction

Someone reproducing this project's results on their own machine, from
scratch, with no prior environment, needs:

1. The exact dependency versions in `backend/requirements.txt`/
   `requirements-dev.txt` and `frontend/package.json`/`package-lock.json` —
   pinned exactly (not `^`/`~` ranges) in every file reviewed for this
   guide, so `pip install -r requirements.txt` and `npm ci` (not `npm
   install`, which can drift from the lockfile) should reproduce the same
   dependency tree.
2. The same two seeds (`42` and `2026`) passed exactly as shown above —
   not substituted for "any seed," since the device-context/training split
   independence depends on using two *different* values, not just two
   seeded calls.
3. An honest acknowledgment that every number produced is against the
   **synthetic** stand-in dataset, not real CICIoMT2024/WUSTL-EHMS-2020 data
   (see `docs/limitations-and-ethics.md` §3) — reproducing this project's
   exact numbers is not the same claim as reproducing a result on real
   IoMT network traffic, and should not be represented as the latter.
4. For the Fabric/blockchain path specifically: a real Fabric binary
   release at `FABRIC_BIN_DIR` — the live-network integration tests are
   gated on this being present and are skipped otherwise, same honest-skip
   pattern as the Postgres tests.
