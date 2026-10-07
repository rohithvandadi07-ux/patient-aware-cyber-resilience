"""Bounded in-memory capture of structured log records, queryable by device_id.

The architecture spec's `get_logs` tool (Section 7 step 4, Section 11's agent
table) implies a queryable log store, but nothing in this codebase has built
one -- `app/core/logging.py` only formats and streams log records to stdout.
Rather than invent a parallel fake "DeviceLog" data model with made-up log
lines for the Investigation Agent to read, this module adds a real
`logging.Handler` that captures records already flowing through the standard
`logging` module (the same ones `configure_logging` formats for stdout) into a
bounded in-memory buffer, filterable by the `device_id`/`incident_id` extras
that `app/core/logging.py`'s own docstring says call sites should attach.

This means `get_logs` only ever returns log lines that something in this
process genuinely logged -- never fabricated evidence -- and as other layers
(scenario runner, detection service, policy engine) start logging with
`extra={"device_id": ...}`, the Investigation Agent's evidence gets richer for
free, with no change needed here.
"""

import logging
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class CapturedLogRecord:
    timestamp: datetime
    level: str
    logger_name: str
    message: str
    device_id: str | None
    incident_id: str | None


class LogCaptureHandler(logging.Handler):
    """A `logging.Handler` that keeps the last `capacity` records in memory,
    in addition to whatever other handlers (e.g. the stdout JSON handler) are
    attached to the root logger. Install once via `install()`; never replaces
    existing handlers.
    """

    def __init__(self, capacity: int = 2000) -> None:
        super().__init__()
        self._records: deque[CapturedLogRecord] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        self._records.append(
            CapturedLogRecord(
                timestamp=datetime.fromtimestamp(record.created, tz=UTC),
                level=record.levelname,
                logger_name=record.name,
                message=record.getMessage(),
                device_id=getattr(record, "device_id", None),
                incident_id=getattr(record, "incident_id", None),
            )
        )

    def query(
        self, device_id: str | None = None, incident_id: str | None = None
    ) -> list[CapturedLogRecord]:
        results = list(self._records)
        if device_id is not None:
            results = [r for r in results if r.device_id == device_id]
        if incident_id is not None:
            results = [r for r in results if r.incident_id == incident_id]
        return results

    def clear(self) -> None:
        self._records.clear()


def install(capacity: int = 2000) -> LogCaptureHandler:
    """Attach a fresh `LogCaptureHandler` to the root logger and return it.
    Callers (app startup, or a test fixture) keep the returned handler to
    query or to `uninstall` later -- this function does not use a hidden
    module-level singleton, so tests can install/uninstall freely without
    leaking state between them."""
    handler = LogCaptureHandler(capacity=capacity)
    logging.getLogger().addHandler(handler)
    return handler


def uninstall(handler: LogCaptureHandler) -> None:
    logging.getLogger().removeHandler(handler)
