"""Incident store: creation, evidence, timeline and lifecycle transitions.

In-memory with an explicit persistence seam, so the backend can swap in the
SQLAlchemy-backed repository without any other subsystem changing. The
in-memory implementation is what the experiment runners and tests use, which
keeps experiments free of database setup.

Every mutation appends a timeline entry carrying an
:class:`AssertionClass`, so the separation between observed fact, inference
and recommendation is preserved in the audit trail rather than only in the
engines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.app.domain.enums import (
    AssertionClass,
    AttackType,
    EvidenceKind,
    IncidentState,
    Severity,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    AgentRunRecord,
    ClinicalRiskResult,
    CyberRiskResult,
    DetectionResult,
    EvidenceRef,
    Incident,
    IncidentTimelineEntry,
    LedgerReceipt,
    NormalisedEvent,
    PatientAwareDecision,
    RecoveryResult,
    ResponseRecord,
)
from incident.correlation import (
    CorrelationDecision,
    IncidentCorrelator,
    extract_source_identities,
)
from incident.lifecycle import assert_transition, can_transition


class IncidentRepository(ABC):
    """Persistence seam."""

    @abstractmethod
    def get(self, incident_id: str) -> Incident | None: ...

    @abstractmethod
    def put(self, incident: Incident) -> None: ...

    @abstractmethod
    def list_all(self) -> list[Incident]: ...

    def list_open(self) -> list[Incident]:
        return [
            i
            for i in self.list_all()
            if i.state not in {IncidentState.RESOLVED, IncidentState.FAILED}
        ]


class InMemoryIncidentRepository(IncidentRepository):
    """Dict-backed repository. Used by tests and experiment runners."""

    def __init__(self) -> None:
        self._items: dict[str, Incident] = {}

    def get(self, incident_id: str) -> Incident | None:
        return self._items.get(incident_id)

    def put(self, incident: Incident) -> None:
        self._items[incident.incident_id] = incident

    def list_all(self) -> list[Incident]:
        return sorted(self._items.values(), key=lambda i: i.created_at)

    def clear(self) -> None:
        self._items.clear()


@dataclass
class IncidentService:
    """Creates and advances incidents.

    The single writer for incident state. Engines and agents call into this
    rather than mutating incidents directly, so every change is validated
    and recorded on the timeline.
    """

    repository: IncidentRepository
    ids: IdFactory
    clock: Clock
    correlator: IncidentCorrelator = field(default_factory=IncidentCorrelator)

    # -- creation / correlation -------------------------------------------
    def ingest_detection(
        self,
        detection: DetectionResult,
        events: list[NormalisedEvent] | None = None,
        attack_started_at: datetime | None = None,
        scenario_id: str | None = None,
    ) -> tuple[Incident, CorrelationDecision]:
        """Attach a detection to an incident, creating one if needed."""
        events = events or []
        identities = extract_source_identities(events)
        decision = self.correlator.correlate(detection, self.repository.list_open(), identities)

        if decision.is_new_incident:
            incident = self._create(detection, attack_started_at, scenario_id)
        else:
            incident = self.repository.get(decision.incident_id or "")
            if incident is None:  # pragma: no cover - defensive
                incident = self._create(detection, attack_started_at, scenario_id)
            else:
                incident = self._attach(incident, detection, decision)

        if events:
            incident = self.add_evidence(
                incident.incident_id,
                self.build_detection_evidence(detection, events, identities),
            )
        return self.repository.get(incident.incident_id) or incident, decision

    def _create(
        self,
        detection: DetectionResult,
        attack_started_at: datetime | None,
        scenario_id: str | None,
    ) -> Incident:
        now = self.clock.now()
        incident = Incident(
            incident_id=self.ids.incident(),
            created_at=now,
            updated_at=now,
            state=IncidentState.DETECTED,
            device_id=detection.device_id,
            attack_type=detection.attack_type,
            confidence=detection.confidence,
            severity=detection.severity,
            detection=detection,
            scenario_id=scenario_id,
            attack_started_at=attack_started_at,
            detected_at=detection.timestamp,
            observations=[self._observation(detection)],
        )
        incident = incident.model_copy(
            update={
                "timeline": [
                    IncidentTimelineEntry(
                        timestamp=now,
                        actor=detection.detector_name,
                        phase="detection",
                        message=(
                            f"Incident opened: {detection.attack_type.value} detected "
                            f"on {detection.device_id} with confidence "
                            f"{detection.confidence:.2f} by "
                            f"{detection.detector_name} "
                            f"({detection.model_version})"
                        ),
                        assertion_class=AssertionClass.INFERENCE,
                        data={
                            "attack_type": detection.attack_type.value,
                            "confidence": detection.confidence,
                            "severity": detection.severity.value,
                            "detector": detection.detector_name,
                            "model_version": detection.model_version,
                        },
                    )
                ]
            }
        )
        self.repository.put(incident)
        return incident

    def _attach(
        self,
        incident: Incident,
        detection: DetectionResult,
        decision: CorrelationDecision,
    ) -> Incident:
        now = self.clock.now()
        updates: dict[str, Any] = {"updated_at": now}

        # --- headline attribution -----------------------------------------
        #
        # An incident's device and attack type must reflect the WEIGHT of
        # corroborating evidence, not whichever detection arrived first.
        #
        # Measured failure that motivated this: on `recon_then_pivot` the
        # first detection in the stream was a FALSE POSITIVE on a device
        # that was never attacked. Because it arrived first it founded the
        # incident, and every subsequent true detection was correlated into
        # it, so the incident was reported against the wrong device with the
        # wrong attack type. One early false positive poisoned the
        # attribution of an entire campaign - a failure mode with a direct
        # real-world analogue in SOC triage.
        #
        # Attribution is therefore recomputed from the accumulated
        # observations each time a detection is attached. The device and
        # attack type with the most corroboration win, with confidence as
        # the tie-break, so an isolated false positive cannot hold the
        # headline against a sustained true signal.
        observations = [*incident.observations, self._observation(detection)]
        updates["observations"] = observations

        device_id, attack_type, confidence, severity = self._attribute(observations)
        updates["device_id"] = device_id
        updates["attack_type"] = attack_type
        updates["confidence"] = confidence
        updates["severity"] = severity

        entry = IncidentTimelineEntry(
            timestamp=now,
            actor=detection.detector_name,
            phase="detection",
            message=(
                f"Correlated detection: {detection.attack_type.value} on "
                f"{detection.device_id} (confidence {detection.confidence:.2f}). "
                f"Rule {decision.rule}: {decision.reason}"
            ),
            assertion_class=AssertionClass.INFERENCE,
            data={
                "correlation_rule": decision.rule,
                "correlation_confidence": decision.confidence,
                "attack_type": detection.attack_type.value,
            },
        )
        updates["timeline"] = [*incident.timeline, entry]
        updated = incident.model_copy(update=updates)
        self.repository.put(updated)
        return updated

    @staticmethod
    def _observation(detection: DetectionResult) -> dict[str, Any]:
        """A compact record of one detection, used for attribution."""
        return {
            "device_id": detection.device_id,
            "attack_type": detection.attack_type.value,
            "confidence": round(detection.confidence, 6),
            "severity": detection.severity.value,
            "detector": detection.detector_name,
            "timestamp": detection.timestamp.isoformat(),
        }

    @staticmethod
    def _attribute(
        observations: list[dict[str, Any]],
    ) -> tuple[str | None, AttackType, float, Severity]:
        """Recompute headline attribution from accumulated observations.

        Weight = sum of detection confidences, so a sustained signal
        outweighs an isolated high-confidence false positive. Device and
        attack type are attributed independently: a campaign's worst-affected
        device and its most-corroborated technique need not come from the
        same single detection.
        """
        from collections import defaultdict

        device_weight: dict[str | None, float] = defaultdict(float)
        attack_weight: dict[str, float] = defaultdict(float)
        for o in observations:
            device_weight[o.get("device_id")] += float(o.get("confidence", 0.0))
            attack_weight[str(o.get("attack_type"))] += float(o.get("confidence", 0.0))

        device_id = max(
            device_weight,
            key=lambda d: (device_weight[d], str(d) or ""),
        )
        attack_name = max(
            attack_weight,
            key=lambda a: (attack_weight[a], a),
        )
        try:
            attack_type = AttackType(attack_name)
        except ValueError:  # pragma: no cover - defensive
            attack_type = AttackType.UNKNOWN

        # Confidence and severity are taken as the maxima observed, since
        # the incident is as serious as its worst corroborated stage.
        confidence = max((float(o.get("confidence", 0.0)) for o in observations), default=0.0)
        order = list(Severity)
        severity = max(
            (Severity(o["severity"]) for o in observations if o.get("severity")),
            key=order.index,
            default=Severity.INFO,
        )
        return device_id, attack_type, confidence, severity

    # -- evidence ----------------------------------------------------------
    def build_detection_evidence(
        self,
        detection: DetectionResult,
        events: list[NormalisedEvent],
        identities: set[str] | None = None,
    ) -> EvidenceRef:
        """Package a detection and its events as content-addressed evidence.

        The payload stays off-chain; only the hash is committed to the
        ledger. Identity fields are recorded here deliberately - evidence is
        for human and agent investigation, unlike the feature matrix, which
        must not see them.
        """
        identities = identities or extract_source_identities(events)
        payload = {
            "detector": detection.detector_name,
            "model_version": detection.model_version,
            "attack_type": detection.attack_type.value,
            "confidence": detection.confidence,
            "anomaly_score": detection.anomaly_score,
            "window_start": detection.window_start.isoformat() if detection.window_start else None,
            "window_end": detection.window_end.isoformat() if detection.window_end else None,
            "contributing_features": detection.contributing_features,
            "event_count": len(events),
            "source_identities": sorted(identities),
            "event_kinds": sorted({e.kind.value for e in events}),
        }
        return EvidenceRef(
            evidence_id=self.ids.evidence(),
            kind=EvidenceKind.DETECTOR_OUTPUT,
            created_at=self.clock.now(),
            assertion_class=AssertionClass.OBSERVED_FACT,
            produced_by=detection.detector_name,
            summary=(
                f"{detection.attack_type.value} detection over "
                f"{len(events)} events on {detection.device_id}"
            ),
            event_ids=[e.event_id for e in events],
            payload=payload,
        ).with_hash()

    def add_evidence(self, incident_id: str, evidence: EvidenceRef) -> Incident:
        incident = self._require(incident_id)
        if not evidence.evidence_hash:
            evidence = evidence.with_hash()
        if any(e.evidence_hash == evidence.evidence_hash for e in incident.evidence):
            # Idempotent: re-adding identical evidence must not inflate the
            # evidence count, which the cyber-risk uncertainty term reads.
            return incident
        now = self.clock.now()
        entry = IncidentTimelineEntry(
            timestamp=now,
            actor=evidence.produced_by,
            phase="evidence",
            message=f"Evidence {evidence.evidence_id} added: {evidence.summary}",
            assertion_class=evidence.assertion_class,
            data={
                "evidence_id": evidence.evidence_id,
                "kind": evidence.kind.value,
                "hash": evidence.evidence_hash,
                "event_count": len(evidence.event_ids),
            },
        )
        updated = incident.model_copy(
            update={
                "evidence": [*incident.evidence, evidence],
                "timeline": [*incident.timeline, entry],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    def verify_evidence(self, incident_id: str) -> dict[str, bool]:
        """Re-derive every evidence hash. Backs the ledger's verifyEvidence."""
        incident = self._require(incident_id)
        return {e.evidence_id: e.verify() for e in incident.evidence}

    # -- lifecycle ---------------------------------------------------------
    def transition(
        self,
        incident_id: str,
        target: IncidentState,
        actor: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> Incident:
        incident = self._require(incident_id)
        assert_transition(incident.state, target)
        now = self.clock.now()
        updates: dict[str, Any] = {
            "state": target,
            "updated_at": now,
            "timeline": [
                *incident.timeline,
                IncidentTimelineEntry(
                    timestamp=now,
                    actor=actor,
                    phase=target.value,
                    message=message,
                    assertion_class=AssertionClass.OBSERVED_FACT,
                    data={
                        "from_state": incident.state.value,
                        "to_state": target.value,
                        **(data or {}),
                    },
                ),
            ],
        }
        if target is IncidentState.RESOLVED:
            updates["resolved_at"] = now
        if target is IncidentState.REINVESTIGATING:
            updates["reinvestigation_count"] = incident.reinvestigation_count + 1
        updated = incident.model_copy(update=updates)
        self.repository.put(updated)
        return updated

    def can_transition(self, incident_id: str, target: IncidentState) -> bool:
        incident = self._require(incident_id)
        return can_transition(incident.state, target).allowed

    # -- attaching subsystem outputs --------------------------------------
    def record_agent_run(self, incident_id: str, run: AgentRunRecord) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        entries = [
            IncidentTimelineEntry(
                timestamp=now,
                actor=f"agent:{run.agent_role.value}",
                phase="agent",
                message=(
                    f"{run.agent_role.value} agent {run.status.value} in "
                    f"{run.duration_ms:.0f}ms with {len(run.tool_calls)} tool calls "
                    f"and {len(run.findings)} findings"
                ),
                assertion_class=AssertionClass.OBSERVED_FACT,
                data={
                    "agent_run_id": run.agent_run_id,
                    "status": run.status.value,
                    "tool_success_rate": run.tool_success_rate,
                    "attempts": run.attempts,
                },
            )
        ]
        # Findings carry their own epistemic status onto the timeline, so an
        # inference is never displayed as an observed fact.
        entries.extend(
            IncidentTimelineEntry(
                timestamp=now,
                actor=f"agent:{run.agent_role.value}",
                phase="finding",
                message=f.statement,
                assertion_class=f.assertion_class,
                data={
                    "confidence": f.confidence,
                    "evidence_ids": f.supporting_evidence_ids,
                },
            )
            for f in run.findings
        )
        updated = incident.model_copy(
            update={
                "agent_runs": [*incident.agent_runs, run],
                "timeline": [*incident.timeline, *entries],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    def record_risk(
        self,
        incident_id: str,
        cyber: CyberRiskResult | None = None,
        clinical: ClinicalRiskResult | None = None,
    ) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        updates: dict[str, Any] = {"updated_at": now}
        entries: list[IncidentTimelineEntry] = []
        if cyber is not None:
            updates["cyber_risk"] = cyber
            entries.append(
                IncidentTimelineEntry(
                    timestamp=now,
                    actor="risk_engine",
                    phase="risk",
                    message=f"Cyber risk {cyber.score:.2f} ({cyber.band.value}). "
                    f"{cyber.explanation}",
                    assertion_class=AssertionClass.INFERENCE,
                    data={"score": cyber.score, "uncertainty": cyber.uncertainty},
                )
            )
        if clinical is not None:
            updates["clinical_risk"] = clinical
            entries.append(
                IncidentTimelineEntry(
                    timestamp=now,
                    actor="risk_engine",
                    phase="risk",
                    message=(
                        f"Clinical risk {clinical.score:.2f} "
                        f"({clinical.band.value}). {clinical.explanation}"
                    ),
                    assertion_class=AssertionClass.INFERENCE,
                    data={
                        "score": clinical.score,
                        "uncertainty": clinical.uncertainty,
                        "life_support_involved": clinical.life_support_involved,
                    },
                )
            )
        updates["timeline"] = [*incident.timeline, *entries]
        updated = incident.model_copy(update=updates)
        self.repository.put(updated)
        return updated

    def record_decision(self, incident_id: str, decision: PatientAwareDecision) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        entry = IncidentTimelineEntry(
            timestamp=now,
            actor="risk_engine",
            phase="decision",
            message=(
                f"Patient-aware decision: {decision.selected_action.value}. {decision.rationale}"
            ),
            # A decision is a RECOMMENDATION: the policy engine, not this
            # record, determines whether it may be executed.
            assertion_class=AssertionClass.RECOMMENDATION,
            data={
                "selected_action": decision.selected_action.value,
                "decision_score": decision.decision_score,
                "cyber_only_action": decision.cyber_only_action.value
                if decision.cyber_only_action
                else None,
                "diverged_from_cyber_only": decision.diverged_from_cyber_only,
                "formulation_version": decision.formulation_version,
            },
        )
        updated = incident.model_copy(
            update={
                "decision": decision,
                "cyber_risk": decision.cyber_risk,
                "clinical_risk": decision.clinical_risk,
                "timeline": [*incident.timeline, entry],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    def record_response(self, incident_id: str, response: ResponseRecord) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        existing = {r.response_id for r in incident.responses}
        responses = (
            [r if r.response_id != response.response_id else response for r in incident.responses]
            if response.response_id in existing
            else [*incident.responses, response]
        )
        entry = IncidentTimelineEntry(
            timestamp=now,
            actor="response_orchestrator",
            phase="response",
            message=(
                f"Response {response.response_id} "
                f"({response.candidate.action_type.value}) is "
                f"{response.state.value}"
                + (f": {response.execution_detail}" if response.execution_detail else "")
            ),
            assertion_class=AssertionClass.OBSERVED_FACT,
            data={
                "response_id": response.response_id,
                "action": response.candidate.action_type.value,
                "state": response.state.value,
                "attempt": response.attempt_number,
            },
        )
        updated = incident.model_copy(
            update={
                "responses": responses,
                "timeline": [*incident.timeline, entry],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    def record_recovery(self, incident_id: str, recovery: RecoveryResult) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        entry = IncidentTimelineEntry(
            timestamp=now,
            actor="recovery_engine",
            phase="recovery",
            message=(
                f"Recovery {recovery.outcome.value}: "
                f"{recovery.checks_passed}/{len(recovery.checks)} checks passed, "
                f"residual risk {recovery.residual_risk:.2f}. "
                f"{recovery.explanation}"
            ),
            assertion_class=AssertionClass.OBSERVED_FACT,
            data={
                "recovery_id": recovery.recovery_id,
                "outcome": recovery.outcome.value,
                "residual_risk": recovery.residual_risk,
                "requires_reinvestigation": recovery.requires_reinvestigation,
            },
        )
        updated = incident.model_copy(
            update={
                "recoveries": [*incident.recoveries, recovery],
                "timeline": [*incident.timeline, entry],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    def record_provenance(self, incident_id: str, receipt: LedgerReceipt) -> Incident:
        incident = self._require(incident_id)
        now = self.clock.now()
        entry = IncidentTimelineEntry(
            timestamp=now,
            actor=f"ledger:{receipt.backend}",
            phase="provenance",
            message=(
                f"Provenance committed: {receipt.provenance_id} as "
                f"transaction {receipt.transaction_id} "
                f"({receipt.latency_ms:.1f}ms)"
            ),
            assertion_class=AssertionClass.OBSERVED_FACT,
            data={
                "provenance_id": receipt.provenance_id,
                "transaction_id": receipt.transaction_id,
                "backend": receipt.backend,
                "record_hash": receipt.record_hash,
            },
        )
        updated = incident.model_copy(
            update={
                "provenance_refs": [*incident.provenance_refs, receipt],
                "timeline": [*incident.timeline, entry],
                "updated_at": now,
            }
        )
        self.repository.put(updated)
        return updated

    # -- queries -----------------------------------------------------------
    def exhausted_actions(self, incident_id: str):
        """Actions already attempted that did not achieve recovery.

        Feeds the risk engine's admissibility gate so re-planning cannot
        repeat a failed action (mandated scenario 3).
        """
        incident = self._require(incident_id)
        failed = []
        for response in incident.responses:
            recovered = any(
                r.response_id == response.response_id and r.outcome.value == "recovered"
                for r in incident.recoveries
            )
            attempted = response.state.value in {
                "executed",
                "failed",
                "recovery_check",
                "residual_risk",
                "reinvestigation",
            }
            if attempted and not recovered:
                failed.append(response.candidate.action_type)
        return failed

    def timeline(self, incident_id: str) -> list[IncidentTimelineEntry]:
        return sorted(self._require(incident_id).timeline, key=lambda e: e.timestamp)

    def _require(self, incident_id: str) -> Incident:
        incident = self.repository.get(incident_id)
        if incident is None:
            raise KeyError(f"unknown incident {incident_id!r}")
        return incident


__all__ = [
    "InMemoryIncidentRepository",
    "IncidentRepository",
    "IncidentService",
]
