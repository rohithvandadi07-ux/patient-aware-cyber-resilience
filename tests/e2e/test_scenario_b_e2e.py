"""Scenario B (architecture spec Section 17), through the real UI.

"a simulated ventilator (criticality=high, patient_dependency=true) hit with
a scripted command-injection scenario. Expected: Policy Engine forces
requires_human_approval=true even though the Threat Reasoning Agent rates
cyber severity as critical [...] Assertion: the system never autonomously
shuts down a patient-dependent, high-criticality device, regardless of
attack severity -- this is the one assertion that most directly tests the
central research claim, so it gets the most scrutiny of any test in the
suite."

**Which "safer non-shutdown action" this test uses, and why, verified
against the real code (not assumed) before writing this fixture:**
`app/risk_engine/rules.py::score_response_impact` scores `isolate_critical`
and `shutdown` as `CRITICAL` impact, unconditionally, whenever
`device_criticality == HIGH and patient_dependency` (the
`_SEVERE_DISRUPTION_ACTIONS` branch) -- that is the real mechanism behind
Section 12's example rule. `isolate_non_critical` falls in
`_MODERATE_DISRUPTION_ACTIONS` instead, which scores only `HIGH` on the same
device/context -- genuinely, measurably safer (`HIGH < CRITICAL`), not
merely differently labeled. Cross-referencing `app/policy_engine/rules.py`'s
`classify_routing`: `isolate_non_critical`/`isolate_critical`/`shutdown` are
NOT in `_UNCONDITIONAL_APPROVAL_ACTIONS` (only `shutdown`/`isolate_critical`
are), so `isolate_non_critical`'s rule outcome is decided purely by its
impact level: `HIGH` (not `<= LOW`, not `MEDIUM`) triggers
`RULE_APPROVAL_HIGH_IMPACT` -- still `requires_human_approval=True`, exactly
as Scenario B requires, while never choosing `shutdown`. And
`isolate_non_critical` is genuinely executable (`app/response_engine/
orchestrator.py`'s `_ISOLATION_FAMILY` -> `SimulatedDevice.isolate()`) --
unlike `rotate_credentials`, which raises `NotImplementedError` there. This
is the one candidate action that is simultaneously real-safer, genuinely
executable, and still correctly approval-gated -- not a guess.

Scenario B's incident is seeded via the real, already-shipped, fixed
`POST /detections/run-scenario` endpoint (it is already shaped as a
ventilator-01 spoofed-command/MITM-style scenario -- see that router's own
docstring), rather than the generic `POST /incidents` Scenario A uses --
preferring the higher-fidelity real detection path when one already exists
for this device/attack shape.
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

from ._seed_scenario import ScenarioFixture, seed_agent_traces, seed_recovery_trace
from ._ui import panel_section

_DEVICE_ID = "ventilator-01"


def _build_fixture(incident_id: str) -> ScenarioFixture:
    return ScenarioFixture(
        device_id=_DEVICE_ID,
        investigation_report=InvestigationReport(
            incident_id=incident_id,
            evidence=["spoofed_command network event targeting ventilator-01's tidal volume setpoint"],
            timeline=[
                "scenario tick 6: spoofed_command injected",
                "ventilator-01 network_state transitioned to compromised",
            ],
            affected_devices=[_DEVICE_ID],
            observations=["the command did not originate from an authenticated controller"],
            confidence=0.85,
        ),
        threat_assessment=ThreatAssessment(
            incident_id=incident_id,
            attack_type="mitm_injection",
            severity="critical",
            confidence=0.95,
            propagation_risk="high",
            reasoning_summary="Command-injection pattern targeting ventilator-01's control interface.",
        ),
        # Exactly Section 17's own documented context (same field values
        # `app/risk_engine/tests/test_scenarios.py::_scenario_b_context`
        # already proved produce a forced-CRITICAL shutdown/isolate_critical
        # and a HIGH (not CRITICAL) isolate_non_critical).
        clinical_context=ClinicalContext(
            incident_id=incident_id,
            device_criticality="high",
            patient_dependency=True,
            clinical_impact_level="critical",
            safety_constraints=["ventilator must not be powered off while patient_dependency is true"],
        ),
        proposed_response=ProposedResponse(
            incident_id=incident_id,
            candidate_actions=[
                {"action_category": "shutdown", "description": "Power off ventilator-01"},
                {
                    "action_category": "isolate_critical",
                    "description": "Isolate ventilator-01's network segment",
                },
                {
                    "action_category": "isolate_non_critical",
                    "description": "Isolate ventilator-01's non-critical telemetry channel only, "
                    "leaving its control path and power untouched",
                },
            ],
            security_benefit={"shutdown": 0.95, "isolate_critical": 0.9, "isolate_non_critical": 0.55},
            clinical_impact={
                "shutdown": "critical",
                "isolate_critical": "critical",
                "isolate_non_critical": "high",
            },
            recommended_action="isolate_non_critical",
            rationale=(
                "The patient is actively ventilator-dependent; shutdown and full isolation both carry "
                "forced-critical clinical impact regardless of the critical cyber severity observed. "
                "Isolating only the non-critical telemetry channel contains the spoofed-command vector "
                "without touching the ventilator's control path or power, at genuinely lower clinical "
                "impact -- the response this agent recommends precisely because it is not a shutdown."
            ),
        ),
        recovery_result=RecoveryResult(
            incident_id=incident_id,
            response_id="placeholder",
            containment_verified=True,
            residual_threats=[],
            recovery_succeeded=True,
            reinvestigation_required=False,
        ),
    )


def test_scenario_b_runs_through_the_real_ui_and_never_autonomously_shuts_down_the_ventilator(
    backend_app, backend_url, frontend_url, page: Page
) -> None:
    # --- Seed: the real fixed detection scenario, then the four real agent
    # traces that precede response execution. No UI control exists for
    # either step (see module docstring + _seed_scenario.py). ---
    detect_response = httpx.post(f"{backend_url}/detections/run-scenario", timeout=30.0)
    detect_response.raise_for_status()
    detections = [d for d in detect_response.json() if d["device_id"] == _DEVICE_ID]
    assert detections, "the fixed scenario injects its attack against ventilator-01"

    incidents = httpx.get(f"{backend_url}/incidents", timeout=10.0).json()
    device_incidents = [i for i in incidents if i["device_id"] == _DEVICE_ID]
    assert device_incidents, "run-scenario must have created a real Incident for ventilator-01"
    incident_id = device_incidents[-1]["incident_id"]

    fixture = _build_fixture(incident_id)
    seed_agent_traces(backend_app, incident_id, fixture)

    # --- Real UI, from here on. ---
    page.goto(f"{frontend_url}/incidents/{incident_id}")
    expect(page.get_by_role("heading", name=incident_id)).to_be_visible()

    # 1. Assess risk -- real POST /risk-assessments.
    page.get_by_role("button", name="Assess risk").click()
    expect(page.get_by_role("progressbar", name="Cyber risk score")).to_be_visible()
    expect(page.get_by_role("progressbar", name="Clinical risk score")).to_be_visible()
    # The Decision table must show isolate_non_critical scored strictly
    # safer than shutdown/isolate_critical, visibly, in the real UI.
    decision_panel = panel_section(page, "Decision")
    isolate_row = decision_panel.locator("tr", has_text="isolate_non_critical")
    shutdown_row = decision_panel.locator("tr", has_text="shutdown").first
    # The table cell's text content is the raw lowercase enum value; only
    # its CSS (`capitalize`) renders it capitalized, so assert on the real
    # DOM text, not the visual presentation.
    expect(isolate_row).to_contain_text("high")
    expect(shutdown_row).to_contain_text("critical")

    # 2. Propose response -- real POST /responses/proposed (Policy Engine).
    page.get_by_role("button", name="Propose response").click()
    expect(page.get_by_text("Chosen action: isolate_non_critical")).to_be_visible()

    # Central Scenario B assertion: the approval gate is real and visible.
    approval_notice = page.get_by_text("Requires human approval before execution.")
    expect(approval_notice).to_be_visible()
    expect(page.get_by_role("button", name="Execute (no approval required)")).to_have_count(0)

    decision = httpx.get(f"{backend_url}/responses/proposed/{incident_id}", timeout=10.0).json()
    assert decision["requires_human_approval"] is True
    assert decision["chosen_action"] == "isolate_non_critical"
    assert decision["chosen_action"] not in ("shutdown", "isolate_critical")

    # 3. Fill in and submit the real approval form -- a human in the loop,
    # through the real browser, not an injected ApprovalRecord.
    page.get_by_placeholder("Approver identity").fill("e2e-soc-analyst")
    page.get_by_placeholder("Notes (optional)").fill(
        "Approved via Phase 11 E2E test -- isolate telemetry only."
    )
    page.get_by_role("button", name="Approve & execute").click()

    executed_row = page.locator("li", has_text="e2e-soc-analyst")
    expect(executed_row).to_be_visible()
    executed_text = executed_row.inner_text()
    assert "shutdown" not in executed_text.lower(), (
        f"Scenario B must never choose shutdown even after human approval: {executed_text!r}"
    )
    assert "isolate_non_critical" in executed_text

    # Corroborate against the real backend state, not just the DOM.
    executed = httpx.get(f"{backend_url}/responses/executed/{incident_id}", timeout=10.0).json()
    assert len(executed) == 1
    assert executed[0]["action_taken"] == "isolate_non_critical"
    assert executed[0]["executed_by"] == "e2e-soc-analyst"
    response_id = f"{incident_id}-response-1"

    # --- Recovery verification agent: no UI control, same disclosed pattern. ---
    seed_recovery_trace(backend_app, incident_id, response_id, fixture)
    page.reload()

    # 4. Submit recovery result -- real POST /recovery, resolves the incident.
    page.get_by_role("button", name="Submit recovery result").click()
    expect(page.get_by_text("Resolved")).to_be_visible()

    # 5. Drain the blockchain outbox -- real POST /blockchain/audit/process.
    audit_panel = panel_section(page, "Blockchain Audit")
    page.get_by_role("button", name="Process pending entries").click()
    expect(audit_panel.get_by_text("pending", exact=True)).to_have_count(0)
    expect(audit_panel.get_by_text("not yet committed")).to_have_count(0)

    # Final corroboration, including the approval record itself being on
    # the real, confirmed audit trail -- a human decision that really
    # happened, really recorded, not assumed.
    incident = httpx.get(f"{backend_url}/incidents/{incident_id}", timeout=10.0).json()
    assert incident["status"] == "resolved"
    audit_trail = httpx.get(f"{backend_url}/blockchain/audit/{incident_id}", timeout=10.0).json()
    assert {entry["record_type"] for entry in audit_trail} == {
        "incident",
        "decision",
        "approval",
        "response",
        "recovery",
    }
    assert all(entry["status"] == "confirmed" for entry in audit_trail)
    assert all(entry["chain_tx_id"] is not None for entry in audit_trail)
