"""Health check endpoint.

Deliberately minimal in Phase 1: it proves the FastAPI app boots and responds, and
nothing more. It does not check database connectivity yet — that's added once
`backend/app/repositories/` has something real to check against, so this endpoint
doesn't silently report "healthy" while lying about a dependency it hasn't actually
verified.
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="patient-aware-cyber-resilience-backend")
