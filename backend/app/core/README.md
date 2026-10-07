# core

Cross-cutting foundation: settings management (environment-variable driven, never
hardcoded), structured logging configuration, and the FastAPI application factory.

Everything in this package is infrastructure, not domain logic. No cybersecurity,
agent, risk, or policy code belongs here.

Status: implemented (Phase 1) — `config.py`, `logging.py`, `app_factory.py`.
