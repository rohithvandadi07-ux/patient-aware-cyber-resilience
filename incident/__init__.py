"""Incident intelligence: lifecycle, correlation, evidence and timeline."""

from incident.correlation import (
    CorrelationConfig,
    CorrelationDecision,
    IncidentCorrelator,
    extract_source_identities,
)
from incident.lifecycle import (
    TERMINAL_STATES,
    TRANSITIONS,
    IllegalTransition,
    assert_transition,
    can_transition,
    validate_machine,
)
from incident.store import (
    IncidentRepository,
    IncidentService,
    InMemoryIncidentRepository,
)

__all__ = [
    "TERMINAL_STATES",
    "TRANSITIONS",
    "CorrelationConfig",
    "CorrelationDecision",
    "IllegalTransition",
    "InMemoryIncidentRepository",
    "IncidentCorrelator",
    "IncidentRepository",
    "IncidentService",
    "assert_transition",
    "can_transition",
    "extract_source_identities",
    "validate_machine",
]
