"""Deterministic guards on LLM agent output.

An agent's output is a claim made by an untrusted component. Where a claim can be
checked against a source of truth the system already holds, it is checked in
code, not only requested in the prompt. This module holds those checks; each is a
small pure function so it can be tested exhaustively without an LLM.

What is grounded, and against what:

* **Healthcare Context Agent**: `device_criticality` and `patient_dependency` must
  equal the device registry's own record of the primary device. The agent's prompt
  already says so; this makes it true even if the model hallucinates or has been
  manipulated. Both fields feed the Policy Engine's hard rule (a patient-dependent
  HIGH-criticality device is never shut down or isolated without a human), so an
  agent that could misstate them could switch that rule off. For the one combination
  that rule exists for (HIGH criticality and patient-dependent), the agent's
  `clinical_impact_level` is also floored at HIGH: disrupting such a device is high
  impact by the system's own definition, so a lower estimate is not accepted.
  `clinical_impact_level` for every other device remains the agent's judgement.
* **Recovery Verification Agent**: it may not report containment verified while new
  attack evidence has arrived on the device since the response was executed. That is
  a count of attack-labelled network events the orchestrator snapshots at execution
  time and compares at verification time, so it does not depend on any clock.
* **Every agent**: the `incident_id` in its output must be the incident it was asked
  about. An answer about a different incident is a validation failure, retried once
  like a schema failure and then a stall.

What is NOT grounded: free-text judgement (reasoning, observations, rationale), the
Threat Reasoning Agent's attack type and severity, and the planner's choice among
candidate actions. Those are LLM judgement; the Risk Engine and the Policy Engine,
which are deterministic, decide what may be done with them.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.schemas.agents import ClinicalContext, RecoveryResult
from app.schemas.device import DeviceState
from app.schemas.enums import DeviceCriticality, ImpactLevel

_IMPACT_ORDER = {ImpactLevel.LOW: 0, ImpactLevel.MEDIUM: 1, ImpactLevel.HIGH: 2, ImpactLevel.CRITICAL: 3}


class IncidentIdMismatchError(ValueError):
    """An agent's output names a different incident than the one it was asked about."""


def check_incident_id(output: BaseModel, expected_incident_id: str) -> None:
    """Raise `IncidentIdMismatchError` if `output` carries an `incident_id` that is
    not `expected_incident_id`. Outputs without that field are not checked."""
    actual = getattr(output, "incident_id", None)
    if actual is not None and actual != expected_incident_id:
        raise IncidentIdMismatchError(
            f"output is about incident {actual!r} but this call was for {expected_incident_id!r}"
        )


def ground_clinical_context(
    context: ClinicalContext, device: DeviceState
) -> tuple[ClinicalContext, list[str]]:
    """Return `context` with registry facts enforced, and a description of each
    correction made (empty if the agent was already consistent)."""
    corrections: list[str] = []
    updates: dict[str, object] = {}

    if context.device_criticality != device.criticality:
        corrections.append(
            f"device_criticality: agent said {context.device_criticality.value!r}, "
            f"registry says {device.criticality.value!r}"
        )
        updates["device_criticality"] = device.criticality
    if context.patient_dependency != device.patient_dependency:
        corrections.append(
            f"patient_dependency: agent said {context.patient_dependency}, "
            f"registry says {device.patient_dependency}"
        )
        updates["patient_dependency"] = device.patient_dependency

    high_stakes = device.criticality == DeviceCriticality.HIGH and device.patient_dependency
    if high_stakes and _IMPACT_ORDER[context.clinical_impact_level] < _IMPACT_ORDER[ImpactLevel.HIGH]:
        corrections.append(
            f"clinical_impact_level: agent said {context.clinical_impact_level.value!r} for a "
            "HIGH-criticality, patient-dependent device; raised to 'high' (the floor for that combination)"
        )
        updates["clinical_impact_level"] = ImpactLevel.HIGH

    if not updates:
        return context, corrections
    return context.model_copy(update=updates), corrections


def ground_recovery_result(
    result: RecoveryResult, new_attack_events: int
) -> tuple[RecoveryResult, list[str]]:
    """Return `result`, overridden to a failed, reinvestigation-required result if it
    claims containment while `new_attack_events` attack-labelled events arrived after
    the response was executed."""
    claims_contained = result.containment_verified or result.recovery_succeeded
    if new_attack_events <= 0 or not claims_contained:
        return result, []

    residual = [
        *result.residual_threats,
        f"{new_attack_events} attack-labelled network event(s) recorded after the response was executed",
    ]
    corrected = result.model_copy(
        update={
            "containment_verified": False,
            "recovery_succeeded": False,
            "reinvestigation_required": True,
            "residual_threats": residual,
        }
    )
    return corrected, [
        f"recovery result claimed containment but {new_attack_events} new attack event(s) arrived after the "
        "response; overridden to containment not verified, reinvestigation required"
    ]
