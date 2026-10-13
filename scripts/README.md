# scripts

Developer scripts: environment setup, dataset download, database migrations. Not
application code — nothing here is imported by `backend/app/`.

Three real, run-verified scripts live here (verified by actually running
each one against this project's current state while writing this note —
not just written and assumed to work):

- **`run_checks.sh`** — runs the backend test suite + `ruff check`, then
  the frontend test suite + lint + build, in one command (the same checks
  `docs/reproducibility.md` §3 lists individually). Advisory steps
  (`pip-audit`, `npm audit`) report findings but never fail the script.
  `./scripts/run_checks.sh --skip-frontend` to run only the backend side;
  `--include-e2e` additionally runs the Playwright E2E suite (needs
  `playwright install chromium` first). Verified: catches a real failing
  `ruff check` (confirmed against this repo's own code at the time of
  writing) and exits non-zero rather than continuing past it.
- **`reset_postgres_dev_db.py`** — creates (or, with `--reset`, drops and
  recreates) the six Postgres-backed tables `backend/app/models/orm.py`
  defines, for local dev use of the opt-in `REPOSITORY_BACKEND=postgres`
  path (`docs/deployment.md` §2). No Alembic exists in this project, so
  this is a blunt create/reset, not a real migration tool. Run from
  `backend/` with its venv active:
  `python ../scripts/reset_postgres_dev_db.py [--reset [--yes]]`. Verified:
  `--help` prints correctly, and with no Postgres reachable (this sandbox's
  own state) it fails with a clear, specific connection error rather than a
  bare traceback — the honest behavior when Postgres isn't running.
- **`tail_fabric_logs.sh`** — tails the real log files the native-binary
  Fabric network (`blockchain/network/`) writes while running
  (`orderer.log`, `peer-HospitalOrg.log`, `peer-SecurityOpsOrg.log`).
  `./scripts/tail_fabric_logs.sh` tails all three together;
  `./scripts/tail_fabric_logs.sh orderer` tails just one. Verified against
  this repo's own real, currently-present log files (written by this
  project's own development history running `start-network.sh`), including
  the "no such log" error path.

Not added: a dataset-download wrapper (`datasets/download_ciciomt2024.py`
already exists and is the real entry point — wrapping it here would add an
indirection layer, not new capability) and an environment-setup script
(the venv/npm-install steps in `docs/deployment.md` §1 are three lines each
and already copy-pasteable; scripting them would mostly be error-message
duplication of what pip/npm already print on failure).
