#!/usr/bin/env python3
"""Drop and recreate every Postgres-backed table for local development.

Only relevant if you're running the opt-in Postgres repository backend
(see docs/deployment.md §2, `Settings.repository_backend == "postgres"`).
Covers exactly the six tables `backend/app/models/orm.py` defines:
incidents, agent_traces, recovery_results, proposed_responses,
executed_responses, outbox_entries. There is no Alembic in this project
(an additive-only `create_all`, by deliberate, disclosed choice -- see
`backend/app/core/db.py`'s own docstring) and therefore no proper "down"
migration either; this script's `--reset` is a blunt drop-everything-and-
recreate, appropriate only for local dev data you don't mind losing.

Does NOT touch NetworkEventStore/TelemetryStore or the IoMT simulator's
DeviceRegistry -- both stay in-memory regardless of REPOSITORY_BACKEND
(see docs/limitations-and-ethics.md §8); there is nothing in Postgres for
either of those to reset.

Usage:
    cd backend && source .venv/bin/activate
    python ../scripts/reset_postgres_dev_db.py            # create missing tables only
    python ../scripts/reset_postgres_dev_db.py --reset    # drop + recreate all 6 tables
    python ../scripts/reset_postgres_dev_db.py --reset --yes   # skip the confirmation prompt

Reads DATABASE_URL the same way the app does (Settings, via .env / the
environment) -- run it from `backend/` with the venv active so `app.core.*`
imports resolve, or set PYTHONPATH to backend/ first.
"""

from __future__ import annotations

import argparse
import os
import sys

# Run as `python ../scripts/reset_postgres_dev_db.py` from `backend/` --
# Python puts this script's own directory (scripts/) on sys.path[0], not
# the current working directory, so `app.*` wouldn't otherwise be
# importable. Prepend cwd explicitly rather than requiring PYTHONPATH to be
# set by hand.
sys.path.insert(0, os.getcwd())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop all 6 tables before recreating them (default: only create missing tables).",
    )
    parser.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt for --reset."
    )
    args = parser.parse_args()

    try:
        from app.core.config import Settings
        from app.core.db import Base, build_engine, create_all_tables, to_sync_url
    except ImportError as exc:
        print(
            f"Could not import the backend app ({exc}).\n"
            "Run this from backend/ with its venv active:\n"
            "  cd backend && source .venv/bin/activate && "
            "python ../scripts/reset_postgres_dev_db.py",
            file=sys.stderr,
        )
        return 1

    settings = Settings()
    sync_url = to_sync_url(settings.database_url)
    print(f"Target database (sync driver): {sync_url}")

    if settings.repository_backend != "postgres":
        print(
            f"Note: REPOSITORY_BACKEND is '{settings.repository_backend}', not 'postgres' -- "
            "the running app won't actually use these tables unless that's set. "
            "Proceeding anyway since you asked explicitly.",
        )

    try:
        engine = build_engine(settings.database_url)
    except Exception as exc:  # pragma: no cover - environment-dependent
        print(f"Could not build a database engine: {exc}", file=sys.stderr)
        return 1

    if args.reset:
        if not args.yes:
            confirm = input(
                f"This will DROP all 6 tables at {sync_url} and recreate them empty. "
                "Type 'yes' to continue: "
            )
            if confirm.strip().lower() != "yes":
                print("Aborted.")
                return 1
        print("Dropping tables...")
        try:
            import importlib

            importlib.import_module("app.models.orm")
            Base.metadata.drop_all(bind=engine)
        except Exception as exc:
            print(
                f"Could not connect to Postgres to drop tables: {exc}\n"
                "Is Postgres running and reachable at the URL above? "
                "See docs/deployment.md §2.",
                file=sys.stderr,
            )
            return 1

    print("Creating tables (create_all -- additive only, no migration history)...")
    try:
        create_all_tables(engine)
    except Exception as exc:
        print(
            f"Could not connect to Postgres to create tables: {exc}\n"
            "Is Postgres running and reachable at the URL above? "
            "See docs/deployment.md §2.",
            file=sys.stderr,
        )
        return 1

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
