"""The controlled tool set.

Implements the sixteen tools named in the specification. Every one is a
pure function over :class:`ToolContext`: there is no shell, no filesystem,
no network, no eval, and no way to reach the simulator's mutation methods.

Two tools deserve particular attention, because they are where a naive
implementation would break the authority boundary:

``propose_safe_action`` (the specification calls it ``execute_safe_action``)
    Does **not** execute anything. It returns a *request* for the response
    orchestrator, which evaluates it against the deterministic policy
    engine. An agent calling this tool has proposed, not acted. Renamed
    from the specification's label because a tool name that overstates its
    authority invites someone to later make it true; see the function's
    docstring.

``calculate_cyber_risk`` / ``calculate_clinical_risk`` / ``evaluate_response_impact``
    Delegate to the deterministic risk engine and return its result
    verbatim. An agent can read a score and reason about it; it cannot
    produce or alter one. There is no tool that writes a risk score.
"""

from __future__ import annotations

from typing import Any

from agents.tools.registry import ToolContext, ToolError, ToolRegistry, ToolSpec
from backend.app.domain.enums import (
    AgentRole as R,
)
from backend.app.domain.enums import (
    EventKind,
    ResponseActionType,
)
from backend.app.domain.enums import (
    ToolAuthority as A,
)
from backend.app.domain.models import ResponseCandidate

ALL_ROLES = frozenset(R)
READERS = frozenset(
    {
        R.INVESTIGATION,
        R.THREAT_REASONING,
        R.HEALTHCARE_CONTEXT,
        R.RESPONSE_PLANNING,
        R.RECOVERY_VERIFICATION,
    }
)

#: Maximum events a single tool call may return. Bounds both the token cost
#: of an agent turn and the blast radius of a pathological query.
MAX_EVENTS = 60


def _package(ctx: ToolContext):
    if ctx.incident_package is None:
        raise ToolError("no incident context package available")
    return ctx.incident_package


# ===========================================================================
# Read-only context tools
# ===========================================================================
def get_incident(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    inc = _package(ctx).incident
    return {
        "incident_id": inc.incident_id,
        "state": inc.state.value,
        "device_id": inc.device_id,
        "attack_type": inc.attack_type.value,
        "confidence": inc.confidence,
        "severity": inc.severity.value,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat(),
        "evidence_count": len(inc.evidence),
        "observation_count": len(inc.observations),
        "reinvestigation_count": inc.reinvestigation_count,
        "detection": (
            {
                "detector": inc.detection.detector_name,
                "model_version": inc.detection.model_version,
                "attack_type": inc.detection.attack_type.value,
                "confidence": inc.detection.confidence,
                "anomaly_score": inc.detection.anomaly_score,
                "contributing_features": inc.detection.contributing_features,
                "notes": inc.detection.notes,
            }
            if inc.detection
            else None
        ),
        # Epistemic reminder carried in the payload itself, so an agent
        # reasoning over this cannot mistake a detector inference for fact.
        "_note": (
            "detection fields are detector INFERENCES, not observed facts; "
            "telemetry and flow records are the observed facts"
        ),
    }


def get_device_profile(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    p = _package(ctx).device_profile
    if p is None:
        raise ToolError("no device profile available for this incident")
    return {
        "device_id": p.device_id,
        "device_type": p.device_type.value,
        "model_name": p.model_name,
        "ward": p.ward,
        "criticality": p.criticality.value,
        "life_support_relevant": p.life_support_relevant,
        "has_redundant_peer": p.has_redundant_peer,
        "redundant_peer_id": p.redundant_peer_id,
        "supports_safe_failover": p.supports_safe_failover,
        "acceptable_interruption_seconds": p.acceptable_interruption_seconds,
        "network_segment": p.network_segment,
        "firmware_version": p.firmware_version,
    }


def get_device_state(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    s = _package(ctx).device_state
    if s is None:
        raise ToolError("no device state available for this incident")
    return {
        "device_id": s.device_id,
        "timestamp": s.timestamp.isoformat(),
        "operational_state": s.operational_state.value,
        "network_state": s.network_state.value,
        "delivering_therapy": s.delivering_therapy,
        "alarm_active": s.alarm_active,
        "alarm_reason": s.alarm_reason,
        "fault_codes": list(s.fault_codes),
        "service_available": s.service_available,
        "active_sessions": s.active_sessions,
        "credentials_version": s.credentials_version,
        "therapy_interrupted_seconds": s.therapy_interrupted_seconds,
    }


def _events_of_kind(ctx: ToolContext, kinds: set[EventKind], limit: int) -> list[dict]:
    events = [e for e in _package(ctx).recent_events if e.kind in kinds]
    events = events[-min(limit, MAX_EVENTS) :]
    out = []
    for e in events:
        row = {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "kind": e.kind.value,
            "device_id": e.device_id,
            "measurements": e.measurements,
            "attributes": e.attributes,
        }
        # Identity is available to agents for investigation - unlike the
        # detection feature matrix, which must never see it.
        for key in (
            "source_ip",
            "destination_ip",
            "source_mac",
            "protocol",
            "source_port",
            "destination_port",
        ):
            value = getattr(e, key, None)
            if value is not None:
                row[key] = value
        out.append(row)
    return out


def get_telemetry(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    rows = _events_of_kind(ctx, {EventKind.TELEMETRY}, limit)
    # The simulator's internal-truth channels are stripped: an agent must
    # reason from what the device REPORTS, exactly as a clinician would,
    # otherwise the spoofing scenario is trivially solved.
    for r in rows:
        r["measurements"] = {
            k: v for k, v in r["measurements"].items() if not k.startswith("truth_")
        }
    return {
        "count": len(rows),
        "events": rows,
        "_note": (
            "these are REPORTED values; under a telemetry-spoofing attack the "
            "reported values may not reflect the device's true state"
        ),
    }


def get_network_events(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 25))
    rows = _events_of_kind(ctx, {EventKind.NETWORK_FLOW}, limit)
    return {"count": len(rows), "events": rows}


def get_security_logs(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 25))
    rows = _events_of_kind(
        ctx,
        {EventKind.AUTH, EventKind.SECURITY_LOG, EventKind.DEVICE_COMMAND, EventKind.DEVICE_STATE},
        limit,
    )
    return {"count": len(rows), "events": rows}


def get_attack_evidence(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    inc = _package(ctx).incident
    return {
        "count": len(inc.evidence),
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "kind": e.kind.value,
                "assertion_class": e.assertion_class.value,
                "produced_by": e.produced_by,
                "summary": e.summary,
                "event_count": len(e.event_ids),
                "hash": e.evidence_hash,
                "verified": e.verify(),
                "payload": e.payload,
            }
            for e in inc.evidence[-MAX_EVENTS:]
        ],
    }


def get_clinical_context(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    p = _package(ctx).device_profile
    if p is None:
        raise ToolError("no device profile available")
    patient = p.patient
    return {
        "device_id": p.device_id,
        "device_criticality": p.criticality.value,
        "life_support_relevant": p.life_support_relevant,
        "has_redundant_peer": p.has_redundant_peer,
        "supports_safe_failover": p.supports_safe_failover,
        "acceptable_interruption_seconds": p.acceptable_interruption_seconds,
        "patient": (
            {
                "synthetic": True,
                "patient_ref": patient.patient_ref,
                "acuity": patient.acuity.value,
                "dependency": patient.dependency.value,
                "on_life_support": patient.on_life_support,
                "clinician_present": patient.clinician_present,
                "tolerable_interruption_minutes": (patient.tolerable_interruption_minutes),
            }
            if patient
            else None
        ),
        "_note": (
            "all patient data is SYNTHETIC and generated by the simulator; "
            "this is a research simulation, not clinical information"
        ),
    }


def get_timeline(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    inc = _package(ctx).incident
    limit = int(args.get("limit", 40))
    entries = sorted(inc.timeline, key=lambda e: e.timestamp)[-min(limit, 100) :]
    return {
        "count": len(entries),
        "entries": [
            {
                "timestamp": e.timestamp.isoformat(),
                "actor": e.actor,
                "phase": e.phase,
                "message": e.message,
                "assertion_class": e.assertion_class.value,
            }
            for e in entries
        ],
    }


def get_exhausted_actions(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Actions already attempted that did not achieve recovery.

    Exposed so the response-planning agent can see, during
    re-investigation, that an action has already failed - rather than
    proposing it again and relying on the risk engine to veto it.
    """
    pkg = _package(ctx)
    return {
        "exhausted_actions": [a.value for a in pkg.exhausted_actions],
        "_note": (
            "these actions were executed for this incident and did not achieve "
            "recovery; proposing one again will be rejected as inadmissible"
        ),
    }


# ===========================================================================
# Compute tools - delegate to the deterministic engine, never override it
# ===========================================================================
def _require_engine(ctx: ToolContext):
    if ctx.risk_engine is None:
        raise ToolError("risk engine is not available in this context")
    return ctx.risk_engine


def calculate_cyber_risk(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    engine = _require_engine(ctx)
    pkg = _package(ctx)
    if pkg.incident.detection is None:
        raise ToolError("incident has no detection to score")
    result = engine.cyber_risk(pkg.incident.detection, pkg.incident.evidence)
    return {
        "score": result.score,
        "band": result.band.value,
        "uncertainty": result.uncertainty,
        "explanation": result.explanation,
        "factors": [
            {
                "name": f.name,
                "value": f.value,
                "weight": f.weight,
                "contribution": f.contribution,
                "rationale": f.rationale,
            }
            for f in result.factors
        ],
        "formulation_version": result.formulation_version,
        "_note": (
            "produced by the deterministic risk engine; this value is "
            "authoritative and cannot be altered by an agent"
        ),
    }


def calculate_clinical_risk(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    engine = _require_engine(ctx)
    pkg = _package(ctx)
    if pkg.device_profile is None:
        raise ToolError("no device profile available to score")
    result = engine.clinical_risk(pkg.device_profile, pkg.device_state)
    return {
        "score": result.score,
        "band": result.band.value,
        "uncertainty": result.uncertainty,
        "life_support_involved": result.life_support_involved,
        "patient_dependency": result.patient_dependency.value,
        "explanation": result.explanation,
        "factors": [
            {
                "name": f.name,
                "value": f.value,
                "weight": f.weight,
                "contribution": f.contribution,
                "rationale": f.rationale,
            }
            for f in result.factors
        ],
        "formulation_version": result.formulation_version,
        "_note": (
            "produced by the deterministic risk engine; this value is "
            "authoritative and cannot be altered by an agent"
        ),
    }


def evaluate_response_impact(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    engine = _require_engine(ctx)
    pkg = _package(ctx)
    raw = str(args["action_type"])
    try:
        action = ResponseActionType(raw)
    except ValueError:
        raise ToolError(
            f"unknown action {raw!r}. Valid actions: {sorted(a.value for a in ResponseActionType)}"
        ) from None

    clinical = (
        engine.clinical_risk(pkg.device_profile, pkg.device_state) if pkg.device_profile else None
    )
    attack = pkg.incident.attack_type
    impact = engine.response_impact(
        ResponseCandidate(action_type=action, target_device_id=pkg.incident.device_id),
        pkg.device_profile,
        pkg.device_state,
        clinical,
        attack,
    )
    return {
        "action_type": impact.action_type.value,
        "security_benefit": impact.security_benefit,
        "clinical_impact": impact.clinical_impact,
        "net_benefit": impact.net_benefit,
        "impact_class": impact.impact_class.value,
        "service_interruption_seconds": impact.service_interruption_seconds,
        "reversible": impact.reversible,
        "backup_available": impact.backup_available,
        "explanation": impact.explanation,
        "_note": (
            "impact_class UNSAFE means this action will be rejected as "
            "inadmissible; do not recommend it"
        ),
    }


def evaluate_candidate_actions(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Evaluate SEVERAL candidate actions in one call.

    WHY THIS EXISTS: evaluating candidates one per tool call cost 13 calls
    and pushed the response-planning agent past its tool budget, so it timed
    out having produced no plan at all. Raising the budget would have hidden
    the real problem - a per-candidate round trip is the wrong granularity
    for a comparison that is inherently over a set. One call now returns the
    whole ranked comparison.
    """
    engine = _require_engine(ctx)
    pkg = _package(ctx)
    requested = args.get("action_types")
    if requested is None:
        actions = list(ResponseActionType)
    else:
        if not isinstance(requested, list):
            raise ToolError("action_types must be a list of action names")
        actions = []
        for raw in requested:
            try:
                actions.append(ResponseActionType(str(raw)))
            except ValueError:
                raise ToolError(
                    f"unknown action {raw!r}. Valid: {sorted(a.value for a in ResponseActionType)}"
                ) from None

    clinical = (
        engine.clinical_risk(pkg.device_profile, pkg.device_state) if pkg.device_profile else None
    )
    attack = pkg.incident.attack_type
    exhausted = set(pkg.exhausted_actions)

    rows = []
    for action in actions:
        impact = engine.response_impact(
            ResponseCandidate(action_type=action, target_device_id=pkg.incident.device_id),
            pkg.device_profile,
            pkg.device_state,
            clinical,
            attack,
        )
        rows.append(
            {
                "action_type": action.value,
                "security_benefit": impact.security_benefit,
                "clinical_impact": impact.clinical_impact,
                "net_benefit": impact.net_benefit,
                "impact_class": impact.impact_class.value,
                "service_interruption_seconds": impact.service_interruption_seconds,
                "reversible": impact.reversible,
                "backup_available": impact.backup_available,
                "already_attempted": action in exhausted,
                "admissible": impact.impact_class.value != "unsafe" and action not in exhausted,
                "explanation": impact.explanation,
            }
        )
    rows.sort(key=lambda r: r["net_benefit"], reverse=True)
    return {
        "attack_type": attack.value,
        "clinical_risk_score": clinical.score if clinical else None,
        "evaluated": len(rows),
        "admissible_count": sum(1 for r in rows if r["admissible"]),
        "candidates": rows,
        "_note": (
            "ranked by net benefit; rows with admissible=false will be "
            "rejected by the risk engine and must not be recommended"
        ),
    }


def evaluate_policy(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Ask the deterministic policy engine what it would permit.

    Read-only: calling this does not authorise anything. It exists so the
    planning agent can avoid proposing an action it knows will be denied,
    rather than discovering that after the fact.
    """
    evaluator = ctx.extra.get("policy_evaluator")
    if evaluator is None:
        raise ToolError("policy engine is not available in this context")
    raw = str(args["action_type"])
    try:
        action = ResponseActionType(raw)
    except ValueError:
        raise ToolError(f"unknown action {raw!r}") from None
    verdict = evaluator(action)
    return {
        "action_type": action.value,
        "decision": verdict.decision.value,
        "impact_class": verdict.impact_class.value,
        "matched_rule": verdict.matched_rule,
        "reasons": list(verdict.reasons),
        "required_role": verdict.required_role,
        "policy_version": verdict.policy_version,
        "_note": (
            "the policy engine is authoritative; an agent cannot override a "
            "DENIED verdict and must not attempt to"
        ),
    }


# ===========================================================================
# Request tools - propose, never perform
# ===========================================================================
def request_human_approval(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Register a request for human approval.

    Returns immediately with a pending request. It does not block, and it
    certainly does not grant approval - a human does that through the
    approval workflow.
    """
    sink = ctx.approval_sink
    raw = str(args["action_type"])
    try:
        action = ResponseActionType(raw)
    except ValueError:
        raise ToolError(f"unknown action {raw!r}") from None
    justification = str(args["justification"])
    if len(justification) < 20:
        raise ToolError(
            "justification must be substantive (at least 20 characters): a "
            "clinician reads this to decide"
        )
    request = {
        "incident_id": ctx.incident_id,
        "action_type": action.value,
        "justification": justification,
        "status": "pending",
    }
    if sink is not None:
        sink(request)
    return {
        **request,
        "_note": "approval is PENDING; no action has been taken or authorised",
    }


def propose_safe_action(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Propose an action for execution. **Does not execute.**

    DEVIATION FROM THE SPECIFICATION, DELIBERATE AND DOCUMENTED.
    The specification names this tool ``execute_safe_action``. It is named
    ``propose_safe_action`` here because it does not execute: it returns a
    request that the response orchestrator evaluates against the
    deterministic policy engine.

    The rename is not cosmetic. A tool name that overstates its authority
    is a latent hazard - it invites a future contributor to "fix" the
    mismatch by making the tool actually actuate, which would make the
    policy engine bypassable and destroy the platform's central safety
    property. The name now matches the semantics, and a CI test rejects
    tool names containing "execute".
    """
    raw = str(args["action_type"])
    try:
        action = ResponseActionType(raw)
    except ValueError:
        raise ToolError(f"unknown action {raw!r}") from None
    pkg = _package(ctx)
    if action in pkg.exhausted_actions:
        raise ToolError(
            f"{action.value} was already attempted for this incident and did "
            "not achieve recovery; propose a different action"
        )
    return {
        "proposed_action": action.value,
        "target_device_id": pkg.incident.device_id,
        "status": "proposed",
        "executed": False,
        "_note": (
            "NOT executed. This is a proposal routed to the deterministic "
            "policy engine, which decides whether it is auto-allowed, "
            "requires human approval, or is denied."
        ),
    }


def verify_recovery(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Run the deterministic recovery checks and return their results."""
    verifier = ctx.extra.get("recovery_verifier")
    if verifier is None:
        raise ToolError("recovery verifier is not available in this context")
    result = verifier()
    return {
        "outcome": result.outcome.value,
        "residual_risk": result.residual_risk,
        "checks_passed": result.checks_passed,
        "checks_total": len(result.checks),
        "requires_reinvestigation": result.requires_reinvestigation,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "observed": c.observed,
                "expected": c.expected,
            }
            for c in result.checks
        ],
        "explanation": result.explanation,
        "_note": "these are deterministic checks against observed device state",
    }


def record_provenance(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Request a provenance record. The orchestrator performs the write."""
    recorder = ctx.extra.get("provenance_recorder")
    if recorder is None:
        raise ToolError("provenance recorder is not available in this context")
    summary = str(args["summary"])
    receipt = recorder(summary)
    return {
        "provenance_id": receipt.provenance_id,
        "transaction_id": receipt.transaction_id,
        "backend": receipt.backend,
        "record_hash": receipt.record_hash,
        "latency_ms": receipt.latency_ms,
    }


# ===========================================================================
# Registry construction
# ===========================================================================
TOOL_SPECS: tuple[tuple[ToolSpec, Any], ...] = (
    # -- read-only -------------------------------------------------------
    (
        ToolSpec(
            name="get_incident",
            authority=A.READ_ONLY,
            description="Get the incident's current state, attribution and detection summary.",
            allowed_roles=READERS,
        ),
        get_incident,
    ),
    (
        ToolSpec(
            name="get_device_profile",
            authority=A.READ_ONLY,
            description=(
                "Get the affected device's static profile, including clinical "
                "criticality and redundancy."
            ),
            allowed_roles=READERS,
        ),
        get_device_profile,
    ),
    (
        ToolSpec(
            name="get_device_state",
            authority=A.READ_ONLY,
            description="Get the device's live operational and network state.",
            allowed_roles=READERS,
        ),
        get_device_state,
    ),
    (
        ToolSpec(
            name="get_telemetry",
            authority=A.READ_ONLY,
            description="Get recent device telemetry as REPORTED by the device (may be spoofed).",
            arguments={"limit": (int, False)},
            allowed_roles=READERS,
        ),
        get_telemetry,
    ),
    (
        ToolSpec(
            name="get_network_events",
            authority=A.READ_ONLY,
            description="Get recent network flow records for the affected device.",
            arguments={"limit": (int, False)},
            allowed_roles=READERS,
        ),
        get_network_events,
    ),
    (
        ToolSpec(
            name="get_security_logs",
            authority=A.READ_ONLY,
            description="Get recent authentication, command and device-state events.",
            arguments={"limit": (int, False)},
            allowed_roles=READERS,
        ),
        get_security_logs,
    ),
    (
        ToolSpec(
            name="get_attack_evidence",
            authority=A.READ_ONLY,
            description="Get the incident's evidence bundle with integrity verification status.",
            allowed_roles=READERS,
        ),
        get_attack_evidence,
    ),
    (
        ToolSpec(
            name="get_clinical_context",
            authority=A.READ_ONLY,
            description="Get the device's clinical role and synthetic patient dependency.",
            allowed_roles=READERS,
        ),
        get_clinical_context,
    ),
    (
        ToolSpec(
            name="get_timeline",
            authority=A.READ_ONLY,
            description="Get the incident timeline, with each entry's epistemic status.",
            arguments={"limit": (int, False)},
            allowed_roles=READERS,
        ),
        get_timeline,
    ),
    (
        ToolSpec(
            name="get_exhausted_actions",
            authority=A.READ_ONLY,
            description=(
                "List actions already attempted for this incident that did not achieve recovery."
            ),
            allowed_roles=frozenset({R.RESPONSE_PLANNING, R.RECOVERY_VERIFICATION}),
        ),
        get_exhausted_actions,
    ),
    # -- compute ---------------------------------------------------------
    (
        ToolSpec(
            name="calculate_cyber_risk",
            authority=A.COMPUTE,
            description=(
                "Compute cyber risk with the deterministic engine. The result is authoritative."
            ),
            allowed_roles=frozenset(
                {R.THREAT_REASONING, R.RESPONSE_PLANNING, R.RECOVERY_VERIFICATION}
            ),
        ),
        calculate_cyber_risk,
    ),
    (
        ToolSpec(
            name="calculate_clinical_risk",
            authority=A.COMPUTE,
            description=(
                "Compute clinical risk with the deterministic engine. The result is authoritative."
            ),
            allowed_roles=frozenset(
                {R.HEALTHCARE_CONTEXT, R.RESPONSE_PLANNING, R.RECOVERY_VERIFICATION}
            ),
        ),
        calculate_clinical_risk,
    ),
    (
        ToolSpec(
            name="evaluate_response_impact",
            authority=A.COMPUTE,
            description="Evaluate the security benefit and clinical cost of one candidate action.",
            arguments={"action_type": (str, True)},
            allowed_roles=frozenset({R.RESPONSE_PLANNING, R.HEALTHCARE_CONTEXT}),
        ),
        evaluate_response_impact,
    ),
    (
        ToolSpec(
            name="evaluate_candidate_actions",
            authority=A.COMPUTE,
            description=(
                "Evaluate and rank MULTIPLE candidate actions in one call. "
                "Prefer this over repeated evaluate_response_impact calls. "
                "Omit action_types to evaluate every available action."
            ),
            arguments={"action_types": (list, False)},
            allowed_roles=frozenset({R.RESPONSE_PLANNING, R.HEALTHCARE_CONTEXT}),
        ),
        evaluate_candidate_actions,
    ),
    (
        ToolSpec(
            name="evaluate_policy",
            authority=A.COMPUTE,
            description=(
                "Ask the policy engine what it would permit for an action. "
                "Read-only; authorises nothing."
            ),
            arguments={"action_type": (str, True)},
            allowed_roles=frozenset({R.RESPONSE_PLANNING}),
        ),
        evaluate_policy,
    ),
    (
        ToolSpec(
            name="verify_recovery",
            authority=A.COMPUTE,
            description="Run the deterministic recovery checks against observed device state.",
            allowed_roles=frozenset({R.RECOVERY_VERIFICATION}),
        ),
        verify_recovery,
    ),
    # -- request / actuate ------------------------------------------------
    (
        ToolSpec(
            name="request_human_approval",
            authority=A.REQUEST_APPROVAL,
            description="Register a pending request for human approval with a justification.",
            arguments={"action_type": (str, True), "justification": (str, True)},
            allowed_roles=frozenset({R.RESPONSE_PLANNING}),
        ),
        request_human_approval,
    ),
    (
        ToolSpec(
            name="propose_safe_action",
            authority=A.ACTUATE,
            description=(
                "Propose an action for the policy engine to rule on. Does NOT "
                "execute. Spec calls this execute_safe_action; renamed because "
                "it only proposes."
            ),
            arguments={"action_type": (str, True)},
            allowed_roles=frozenset({R.RESPONSE_PLANNING}),
        ),
        propose_safe_action,
    ),
    (
        ToolSpec(
            name="record_provenance",
            authority=A.LEDGER_WRITE,
            description="Request a provenance record on the permissioned ledger.",
            arguments={"summary": (str, True)},
            allowed_roles=frozenset({R.RECOVERY_VERIFICATION}),
        ),
        record_provenance,
    ),
)


def build_registry(ids) -> ToolRegistry:
    """Construct the registry with the full controlled tool set."""
    registry = ToolRegistry(ids)
    for spec, fn in TOOL_SPECS:
        registry.register(spec, fn)
    return registry


__all__ = ["MAX_EVENTS", "TOOL_SPECS", "build_registry"]
