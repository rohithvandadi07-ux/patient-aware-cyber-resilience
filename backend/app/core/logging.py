"""Structured logging configuration.

Every request is expected to log through the standard `logging` module using
loggers named after their module (`logging.getLogger(__name__)`). This module only
configures *how* log records are formatted and where they go — it introduces no
new logging API, so call sites stay ordinary Python.

Audit-relevant events (incident creation, policy decisions, approvals, responses)
will carry an `incident_id` field via `extra=` once those layers exist (Phase 2+);
this module's JSON formatter already supports arbitrary extra fields so that wiring
requires no change here.
"""

import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Minimal structured JSON log formatter.

    Deliberately dependency-free (no `python-json-logger`) — this is foundation
    code and the brief warns against adding dependencies without justification.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Carry through any structured extras the caller attached, e.g.
        # logger.info("incident created", extra={"incident_id": "..."})
        reserved = set(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys())
        for key, value in vars(record).items():
            if key not in reserved and key not in payload:
                payload[key] = value

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure root logging once, at process startup.

    Idempotent-ish: clears any existing handlers on the root logger first so this
    is safe to call multiple times in tests without duplicating log lines.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )

    root.addHandler(handler)
