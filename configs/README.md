# configs

Environment-specific configuration (YAML), kept out of code so nothing is
hardcoded. Actual secrets stay in `.env` (gitignored) — this directory holds
non-secret, environment-shaped configuration only (model hyperparameter defaults,
policy thresholds, service endpoints for local/dev/test).
