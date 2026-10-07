"""Shared FastAPI dependencies.

Phase 2 introduces the first piece of app-wide state: a single in-memory
DeviceRegistry, created once at app startup and handed to routes via
dependency injection — never imported as a bare module-level global, so tests
can override it with `app.dependency_overrides`.
"""

from fastapi import Request

from app.iomt_simulator.registry import DeviceRegistry


def get_device_registry(request: Request) -> DeviceRegistry:
    return request.app.state.device_registry
