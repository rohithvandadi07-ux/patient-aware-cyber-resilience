"""Sync SQLAlchemy engine/session plumbing for the Postgres-backed repository
implementations (`Settings.repository_backend == "postgres"`).

**Why sync, not async, even though `asyncpg` has been in `requirements.txt`
since Phase 1 and FastAPI route handlers are all `async def`.** Every
repository in this codebase (`app/repositories/*.py`, `app/blockchain/
outbox.py`) was deliberately shaped so that swapping its in-memory storage
for a real one would be "a constructor change for callers, not an API
rewrite" (each module's own docstring says this). That promise only holds if
the new implementation's public methods keep the exact same synchronous
signatures the in-memory ones already have -- every call site across
`app/api/`, `app/agents/tools.py`, `app/response_engine/orchestrator.py`,
and `app/recovery/engine.py` calls `repo.create(...)`/`repo.record(...)`
directly, with no `await`, because the in-memory methods return immediately.
An async rewrite would need `await` added at every one of those call sites
(and in the ~30 test files that exercise them) to avoid silently returning
un-awaited coroutines -- a far larger, riskier change than "migrate the
storage." Choosing a sync driver (`psycopg`, v3, sync by default) instead
keeps every existing call site correct unchanged, at a real, disclosed cost:
a blocking DB round-trip inside an `async def` route handler blocks that
worker's event loop for the duration of the call. For this research
prototype's actual scale (one researcher's simulated three-device hospital,
not a production multi-tenant service) that tradeoff is acceptable and
explicitly documented here rather than hidden; a real high-concurrency
deployment would want the async rewrite this pass deliberately did not do
(see `app/models/README.md`'s "what this did NOT do" section).

**Why no Alembic.** This pass is additive-only (`create_all`, below) against
a schema this project still controls completely, with no production data in
it yet. A real migration tool is the right next step the moment either of
those stops being true -- not invented here just to look more complete.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for every ORM model in `app/models/orm.py`."""


def to_sync_url(database_url: str) -> str:
    """`Settings.database_url` defaults to an asyncpg DSN
    (`postgresql+asyncpg://...`) because Phase 1 anticipated an async
    driver before any repository actually used the database. Rather than
    add a second, separately configured URL for what is, in Postgres terms,
    the exact same database, this swaps the dialect+driver prefix for
    `psycopg` (v3, sync by default) -- one setting stays the single source
    of truth for where the database is, regardless of which driver talks
    to it.
    """
    if "+asyncpg" in database_url:
        return database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://")
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def build_engine(database_url: str) -> Engine:
    return create_engine(to_sync_url(database_url), pool_pre_ping=True, future=True)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def create_all_tables(engine: Engine) -> None:
    """Creates every table in `Base.metadata` that doesn't already exist.

    Imports `app.models.orm` for its side effect of registering every ORM
    class on `Base.metadata` -- a plain `from app.models import orm` would
    get flagged as an unused import by `ruff`, so the import itself is the
    point, done explicitly via `importlib` rather than suppressed with a
    `noqa` that would hide a genuinely unused import anywhere else.
    """
    import importlib

    importlib.import_module("app.models.orm")
    Base.metadata.create_all(bind=engine)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """One session per repository call: committed on success, rolled back
    and re-raised on any exception. The simplest correct unit-of-work for a
    sync driver invoked from several concurrent request handlers, each of
    which should see its own short-lived transaction rather than one shared
    session mutated from multiple places.
    """
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
