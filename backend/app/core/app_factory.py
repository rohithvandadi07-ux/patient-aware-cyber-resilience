"""FastAPI application factory.

Kept as a factory (rather than a module-level `app = FastAPI()`) so tests can
construct an isolated app instance with overridden settings/dependencies, and so
later phases can register new routers in one place as they're built, instead of
editing a growing `main.py`.
"""

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and return a configured FastAPI application.

    Args:
        settings: Optional explicit settings, primarily for tests. Defaults to the
            cached process-wide settings.
    """
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_output=settings.log_json)

    app = FastAPI(
        title=settings.app_name,
        description=(
            "Research-grade, patient-aware autonomous cyber-resilience platform for "
            "healthcare IoMT. See /docs/architecture.md for the full architecture "
            "specification."
        ),
        version="0.1.0",
        debug=settings.debug,
    )

    _register_routers(app)

    return app


def _register_routers(app: FastAPI) -> None:
    """Register all API routers.

    Phase 1 registers only the health router. Each later phase (simulator,
    detection, agents, risk engine, etc.) adds its router here as it's built —
    this function is the single place that has to change to wire in a new
    resource.
    """
    from app.api.health import router as health_router

    app.include_router(health_router)
