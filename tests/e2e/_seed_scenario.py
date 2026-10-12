"""Shared scaffolding for seeding a real Scenario A/B incident on a live,
running backend, before Playwright drives the rest through the real UI.

**Anti-fabrication disclosure, same as `backend/tests/test_lifecycle_integration.py`:**
there is no HTTP endpoint to run an agent (by design -- `app/agents/README.md`:
no live LLM backend is wired in anywhere in this project, and no orchestrator
sequences the five agents automatically yet). So, exactly like that test, this
module calls the five real agent functions directly, in pipeline order,
scripting each one's structured LLM output via `MockLLMClient` -- the
project's own established test double. The scripted outputs are authored to
match the architecture spec's Section 17 scenario descriptions (and, for
Scenario A/B specifically, the exact `ThreatAssessment`/`ClinicalContext`
field values already proven at the risk-engine level by
`app/risk_engine/tests/test_scenarios.py`), but they are not live model
output, and nothing in this suite claims otherwise.

Everything downstream of agent seeding -- risk assessment, proposing a
response, executing it (including the human-approval step), submitting
recovery, draining the blockchain outbox -- is driven through the real
rendered SOC dashboard by Playwright in the two `test_scenario_*_e2e.py`
modules, against a real running backend over real HTTP. That is the part
this suite exists to prove (architecture spec Section 19's Phase 11 gate:
"Scenario A and B run through the real UI, not just backend tests") --
seeding the agent traces is the one step with no UI control to click,
because by design none exists.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.agents.healthcare_context import assess_clinical_context
from app.agents.investigation import investigate
from app.agents.llm_client import MockLLMClient
from app.agents.recovery_verification import verify_recovery
from app.agents.response_planning import plan_response
from app.agents.threat_reasoning import assess_threat
from app.agents.tools import AgentToolkit
from app.repositories.log_capture import install, uninstall
from app.schemas.agents import (
    ClinicalContext,
    InvestigationReport,
    ProposedResponse,
    RecoveryResult,
    ThreatAssessment,
)


def build_toolkit(app, log_handler) -> AgentToolkit:
    """Mirrors `backend/tests/test_lifecycle_integration.py::_build_toolkit`
    exactly (wiring an `AgentToolkit` to the live app's own `app.state`
    singletons, not a disconnected copy) -- duplicated rather than imported
    across the `backend/tests` <-> top-level `tests/` package boundary,
    which pytest's two independent rootdirs make awkward to share cleanly.
    """
    return AgentToolkit(
        device_registry=app.state.device_registry,
        incident_repository=app.state.incident_repository,
        network_event_store=app.state.network_event_store,
        telemetry_store=app.state.telemetry_store,
        log_handler=log_handler,
        trace_recorder=app.state.agent_trace_recorder,
        recovery_result_repository=app.state.recovery_result_repository,
    )


@dataclass(frozen=True)
class ScenarioFixture:
    """Everything needed to seed one scenario's five agent traces for a
    real incident_id already created on the live backend."""

    device_id: str
    investigation_report: InvestigationReport
    threat_assessment: ThreatAssessment
    clinical_context: ClinicalContext
    proposed_response: ProposedResponse
    recovery_result: RecoveryResult


def seed_agent_traces(app, incident_id: str, fixture: ScenarioFixture) -> None:
    """Runs the four pre-response-execution agents for real against the
    live app's own state, via a disclosed `MockLLMClient`, recording real
    traces. `recovery_verification` is seeded separately (`seed_recovery_trace`)
    since it depends on the response actually having been executed first --
    through the real UI, by the time the test calls it.
    """
    log_handler = install()
    try:
        toolkit = build_toolkit(app, log_handler)

        report = investigate(
            MockLLMClient(responses=[fixture.investigation_report.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            device_id=fixture.device_id,
        )
        assert report == fixture.investigation_report

        threat = assess_threat(
            MockLLMClient(responses=[fixture.threat_assessment.model_dump_json()]),
            toolkit,
            report=report,
            device_id=fixture.device_id,
        )
        assert threat == fixture.threat_assessment

        context = assess_clinical_context(
            MockLLMClient(responses=[fixture.clinical_context.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            affected_devices=[fixture.device_id],
        )
        assert context == fixture.clinical_context

        proposal = plan_response(
            MockLLMClient(responses=[fixture.proposed_response.model_dump_json()]),
            toolkit,
            threat=threat,
            context=context,
            risk_score=None,
        )
        assert proposal == fixture.proposed_response
    finally:
        uninstall(log_handler)


def seed_recovery_trace(app, incident_id: str, response_id: str, fixture: ScenarioFixture) -> RecoveryResult:
    """Runs the recovery_verification agent for real, scripted to match
    `fixture.recovery_result` (with the real `response_id` the UI's
    executed response actually produced)."""
    recovery_result = fixture.recovery_result.model_copy(update={"response_id": response_id})
    log_handler = install()
    try:
        toolkit = build_toolkit(app, log_handler)
        real_recovery = verify_recovery(
            MockLLMClient(responses=[recovery_result.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            response_id=response_id,
            device_id=fixture.device_id,
        )
        assert real_recovery == recovery_result
        return real_recovery
    finally:
        uninstall(log_handler)


def create_incident_via_api(base_url: str, *, incident_id: str, device_id: str, attack_type: str) -> None:
    """Seeds Scenario A's incident the honest way: the real, already-shipped
    `POST /incidents` endpoint (Phase 9) -- not a new scenario-specific
    endpoint, which `app/api/detections.py`'s own docstring warns against
    inventing ("exposing free-form scenario injection here would be
    building an unplanned feature"). There is genuinely no HTTP-triggerable
    DoS-on-infusion-pump scenario, so this is the real, generic, pre-existing
    path for "a detection created this incident" instead.
    """
    response = httpx.post(
        f"{base_url}/incidents",
        json={
            "incident_id": incident_id,
            "device_id": device_id,
            "attack_type": attack_type,
            "evidence_ref": f"e2e-seed/{incident_id}",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
        timeout=10.0,
    )
    response.raise_for_status()
