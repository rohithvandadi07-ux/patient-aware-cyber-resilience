# configs

Architecture spec §6 planned this directory for environment-specific YAML
configuration, kept out of code. Checked against the real code while writing
`docs/deployment.md`/`docs/reproducibility.md` (Phase 15+ documentation
pass): **there is currently no separate config file this directory should
hold**, and that is stated here directly rather than left as an empty
placeholder implying something is coming.

What actually configures this system today, and where:

- **Environment/service settings** (`API_PORT`, `CORS_ALLOWED_ORIGINS`,
  `DATABASE_URL`, `REPOSITORY_BACKEND`, `FABRIC_CLIENT_MODE`, log level,
  etc.) live in `.env` (gitignored; `.env.example` documents every key) and
  are read by `backend/app/core/config.py`'s `Settings`
  (`pydantic-settings`) — not YAML.
- **Policy thresholds** (which `response_impact`/`device.patient_dependency`
  combinations require human approval) are explicit, named Python functions
  in `backend/app/policy_engine/rules.py` — deliberately code, not a config
  file, so they are "reviewable code" an LLM-driven config edit could not
  silently influence (architecture spec §13's own stated reasoning; grepped
  for `yaml`/`config` in that module while writing this note — no hits).
- **Model hyperparameters** (train/test split, `random_state`) are CLI
  arguments with code-level defaults in `backend/app/cybersecurity/
  training.py` (`--seed`, etc.), not a separate hyperparameter file.

If a genuine need for environment-specific YAML config arises later (e.g.
per-environment policy threshold overrides), add it here then — this note
should be replaced with real files at that point, not kept as a stale
placeholder.
