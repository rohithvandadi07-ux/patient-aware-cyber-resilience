"""Scenario A (architecture spec Section 17), through the real UI.

"a simulated infusion pump (criticality=low, patient_dependency=false) hit
with a scripted DoS scenario. Expected: Policy Engine auto-approves network
isolation [...] Assertion: no human-approval step was required, and the
chosen action was not a shutdown."

The `ThreatAssessment`/`ClinicalContext` field values below are exactly the
ones `app/risk_engine/tests/test_scenarios.py` already proved, at the
risk-engine level, make `isolate_non_critical` score `response_impact=LOW`
on this device -- which is what forces the real Policy Engine's
`RULE_AUTONOMOUS_LOW_IMPACT` to fire (`app/policy_engine/rules.py`) instead
of a rule that would require approval. Nothing about that scoring is
re-derived here; this test's job is to prove it actually happens through the
real running system when a human drives the real dashboard, not to
re-prove the rule table itself (that's Phase 5/6's own test suites' job).

Seeding the incident and its agent traces has no UI to click (see
`_seed_scenario.py`'s module docstring for why). Every step downstream of
that -- assessing risk, proposing the response, executing it, submitting
recovery, draining the blockchain outbox -- is driven by Playwright clicking
the real rendered dashboard, against the real running backend over real
HTTP.
"""

from __future__ import annotations

import httpx
from playwright.sync_api import Page, expect

from app.schemas.agents import (
    ClinicalContext,
    InvestigationReport,
    ProposedResponse,
    RecoveryResult,
    ThreatAssessment,
)

from ._seed_scenario import ScenarioFixture, create_incident_via_api, seed_agent_traces, seed_recovery_trace
from ._ui import panel_section

_INCIDENT_ID = "e2e-scenario-a"
_DEVICE_ID = "infusion-pump-01"

_FIXTURE = ScenarioFixture(
    device_id=_DEVICE_ID,
    investigation_report=InvestigationReport(
        incident_id=_INCIDENT_ID,
        evidence=["flood of malformed network requests targeting infusion-pump-01's control port"],
        timeline=[
            "scenario tick 6: DoS flood begins against infusion-pump-01",
            "infusion-pump-01 network interface saturated",
        ],
        affected_devices=[_DEVICE_ID],
        observations=["no command payload was accepted -- this is a volumetric flood, not a takeover"],
        confidence=0.9,
    ),
    threat_assessment=ThreatAssessment(
        incident_id=_INCIDENT_ID,
        attack_type="dos",
        severity="high",
        confidence=0.9,
        propagation_risk="low",
        reasoning_summary="DoS flood pattern against infusion-pump-01's network interface.",
    ),
    clinical_context=ClinicalContext(
        incident_id=_INCIDENT_ID,
        device_criticality="low",
        patient_dependency=False,
        clinical_impact_level="low",
        safety_constraints=[],
    ),
    proposed_response=ProposedResponse(
        incident_id=_INCIDENT_ID,
        candidate_actions=[
            {
                "action_category": "isolate_non_critical",
                "description": "Isolate infusion-pump-01's network segment pending investigation",
            },
            {
                "action_category": "shutdown",
                "description": "Shut down infusion-pump-01",
            },
        ],
        security_benefit={"isolate_non_critical": 0.7, "shutdown": 0.95},
        clinical_impact={"isolate_non_critical": "low", "shutdown": "medium"},
        recommended_action="isolate_non_critical",
        rationale=(
            "Isolating the network segment stops the flood without powering off a device the patient "
            "is not currently dependent on; shutdown offers only marginally higher security benefit "
            "for needlessly higher clinical disruption."
        ),
    ),
    recovery_result=RecoveryResult(
        incident_id=_INCIDENT_ID,
        response_id="placeholder",  # overwritten by seed_recovery_trace with the real executed response_id
        containment_verified=True,
        residual_threats=[],
        recovery_succeeded=True,
        reinvestigation_required=False,
    ),
)


def test_scenario_a_runs_through_the_real_ui_and_auto_approves_a_non_shutdown_action(
    backend_app, backend_url, frontend_url, page: Page
) -> None:
    # --- Seed: a real incident (via the real, pre-existing POST /incidents
    # endpoint -- see _seed_scenario.py's docstring for why not a new
    # scenario-specific endpoint), then the four real agent traces that
    # precede response execution. No UI control exists for either step. ---
    create_incident_via_api(backend_url, incident_id=_INCIDENT_ID, device_id=_DEVICE_ID, attack_type="dos")
    seed_agent_traces(backend_app, _INCIDENT_ID, _FIXTURE)

    # --- Real UI, from here on. ---
    page.goto(f"{frontend_url}/incidents/{_INCIDENT_ID}")
    expect(page.get_by_role("heading", name=_INCIDENT_ID)).to_be_visible()

    # 1. Assess risk -- real POST /risk-assessments, triggered by a real click.
    page.get_by_role("button", name="Assess risk").click()
    expect(page.get_by_text("Cyber risk score")).to_be_visible()
    expect(page.get_by_text("Clinical risk score")).to_be_visible()
    # The dual-risk panel must show two genuinely distinct, independently
    # computed scores -- not one value duplicated into both panels.
    cyber_meter = page.get_by_role("progressbar", name="Cyber risk score")
    clinical_meter = page.get_by_role("progressbar", name="Clinical risk score")
    expect(cyber_meter).to_be_visible()
    expect(clinical_meter).to_be_visible()

    # 2. Propose response -- real POST /responses/proposed (Policy Engine).
    page.get_by_role("button", name="Propose response").click()
    expect(page.get_by_text("Chosen action:")).to_be_visible()

    # Central Scenario A assertion #1: no human-approval step appears.
    expect(page.get_by_text("Requires human approval before execution.")).to_have_count(0)
    execute_button = page.get_by_role("button", name="Execute (no approval required)")
    expect(execute_button).to_be_visible()

    # 3. Execute -- real POST /responses/executed, auto-approved path.
    execute_button.click()
    executed_row = page.locator("li", has_text="by system at")
    expect(executed_row).to_be_visible()
    executed_text = executed_row.inner_text()
    assert "shutdown" not in executed_text.lower(), (
        f"Scenario A's chosen action must not be a shutdown: {executed_text!r}"
    )

    # Confirm against the real backend state, not just the DOM, which action
    # actually executed, so the UI assertion above is corroborated by the
    # real persisted record.
    executed = httpx.get(f"{backend_url}/responses/executed/{_INCIDENT_ID}", timeout=10.0).json()
    assert len(executed) == 1
    assert executed[0]["action_taken"] == "isolate_non_critical"
    response_id = f"{_INCIDENT_ID}-response-1"

    # --- Recovery verification agent: no UI control, same disclosed pattern. ---
    seed_recovery_trace(backend_app, _INCIDENT_ID, response_id, _FIXTURE)
    page.reload()

    # 4. Submit recovery result -- real POST /recovery, resolves the incident.
    recovery_panel = panel_section(page, "Recovery")
    page.get_by_role("button", name="Submit recovery result").click()
    expect(recovery_panel.get_by_text("Recovery succeeded:")).to_be_visible()
    expect(page.get_by_text("Resolved")).to_be_visible()

    # 5. Drain the blockchain outbox -- real POST /blockchain/audit/process.
    audit_panel = panel_section(page, "Blockchain Audit")
    page.get_by_role("button", name="Process pending entries").click()
    expect(audit_panel.get_by_text("pending", exact=True)).to_have_count(0)
    expect(audit_panel.get_by_text("not yet committed")).to_have_count(0)

    # Final corroboration against the real backend, not just rendered text.
    incident = httpx.get(f"{backend_url}/incidents/{_INCIDENT_ID}", timeout=10.0).json()
    assert incident["status"] == "resolved"
    audit_trail = httpx.get(f"{backend_url}/blockchain/audit/{_INCIDENT_ID}", timeout=10.0).json()
    assert all(entry["status"] == "confirmed" for entry in audit_trail)
    assert all(entry["chain_tx_id"] is not None for entry in audit_trail)
