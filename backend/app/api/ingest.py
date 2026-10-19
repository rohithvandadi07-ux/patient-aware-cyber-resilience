"""`/ingest` -- alerts from external detectors (Suricata EVE, Wazuh, generic webhook).

Each accepted alert is recorded as a `NetworkEvent` (so the investigation
agents see it as evidence for that device) and opens one incident per distinct
(device, attack type) in the batch, from the most confident alert, with
blockchain provenance -- the same shape as `/detections/score-flows`. No ML
model is involved: the confidence stored is a documented mapping of the
source's own severity (see `app/ingestion/adapters.py`).

Device identification, in order: the request's explicit `device_id`; else the
first alert identifier (Wazuh agent name, Suricata/Wazuh IPs -- destination
first for Suricata) that is a registered device_id; else an IP found in
`Settings.device_ip_map`. An alert that matches nothing is rejected, never
assigned to a guessed device. Malformed alerts are rejected individually;
valid records that are not alerts (e.g. Suricata `flow`/`stats`) are ignored.
"""

from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.dependencies import (
    get_device_registry,
    get_incident_repository,
    get_network_event_store,
    get_outbox_repository,
)
from app.blockchain.hashing import hash_payload
from app.blockchain.outbox import OutboxRepository, enqueue_incident
from app.core.config import Settings, get_settings
from app.ingestion.adapters import ADAPTERS, AlertParseError, NormalizedAlert, NotAnAlertError
from app.iomt_simulator.registry import DeviceRegistry
from app.repositories.incidents import IncidentRepository
from app.repositories.telemetry_events import NetworkEventStore
from app.schemas.blockchain import IncidentProvenance
from app.schemas.events import NetworkEvent

router = APIRouter(prefix="/ingest", tags=["ingest"])


class AlertBatchRequest(BaseModel):
    source: Literal["generic", "suricata_eve", "wazuh"]
    device_id: str | None = Field(
        default=None,
        description="Apply to every alert in the batch (a sensor dedicated to one device). "
        "Must be a registered device.",
    )
    alerts: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class AlertOutcome(BaseModel):
    index: int
    status: Literal["accepted", "ignored", "rejected"]
    device_id: str | None = None
    attack_type: str | None = None
    confidence: float | None = None
    incident_id: str | None = None
    reason: str | None = None


class AlertBatchResponse(BaseModel):
    source: str
    outcomes: list[AlertOutcome]
    incident_ids: list[str] = Field(
        description="One incident per distinct (device, attack type) in the batch."
    )


def _resolve_device(
    alert: NormalizedAlert, explicit: str | None, known: set[str], ip_map: dict[str, str]
) -> str | None:
    if explicit:
        return explicit
    for candidate in alert.candidates:
        if candidate in known:
            return candidate
    for candidate in alert.candidates:
        mapped = ip_map.get(candidate)
        if mapped in known:
            return mapped
    return None


@router.post("/alerts", response_model=AlertBatchResponse)
async def ingest_alerts(
    request: AlertBatchRequest,
    registry: DeviceRegistry = Depends(get_device_registry),
    incident_repo: IncidentRepository = Depends(get_incident_repository),
    outbox_repo: OutboxRepository = Depends(get_outbox_repository),
    event_store: NetworkEventStore = Depends(get_network_event_store),
    settings: Settings = Depends(get_settings),
) -> AlertBatchResponse:
    known = {d.device_id for d in registry.list_devices()}
    if request.device_id is not None and request.device_id not in known:
        raise HTTPException(status_code=404, detail=f"Device '{request.device_id}' not found")

    parse = ADAPTERS[request.source]
    outcomes: list[AlertOutcome] = []
    events: list[NetworkEvent] = []
    best: dict[tuple[str, str], NormalizedAlert] = {}
    keys: dict[int, tuple[str, str]] = {}

    for index, raw in enumerate(request.alerts):
        try:
            alert = parse(raw)
        except NotAnAlertError as exc:
            outcomes.append(AlertOutcome(index=index, status="ignored", reason=str(exc)))
            continue
        except AlertParseError as exc:
            outcomes.append(AlertOutcome(index=index, status="rejected", reason=str(exc)))
            continue

        device_id = _resolve_device(alert, request.device_id, known, settings.device_ip_map)
        if device_id is None:
            outcomes.append(
                AlertOutcome(
                    index=index,
                    status="rejected",
                    attack_type=alert.attack_type.value,
                    reason="no registered device matches this alert "
                    f"(identifiers: {list(alert.candidates) or 'none'}); send device_id or set DEVICE_IP_MAP",
                )
            )
            continue

        events.append(
            NetworkEvent(
                device_id=device_id,
                timestamp=alert.timestamp,
                event_type=f"external_alert:{alert.attack_type.value}",
                source=alert.source,
                payload={
                    "summary": alert.summary,
                    "severity": alert.severity_hint.value,
                    "reference": alert.reference,
                    **alert.details,
                },
            )
        )
        key = (device_id, alert.attack_type.value)
        keys[index] = key
        if key not in best or alert.confidence > best[key].confidence:
            best[key] = alert
        outcomes.append(
            AlertOutcome(
                index=index,
                status="accepted",
                device_id=device_id,
                attack_type=alert.attack_type.value,
                confidence=alert.confidence,
            )
        )

    event_store.record_many(events)

    incident_for_key: dict[tuple[str, str], str] = {}
    for (device_id, attack_type), alert in best.items():
        incident_id = f"INC-{device_id}-{uuid4().hex[:8]}"
        incident = incident_repo.create(incident_id, device_id=device_id)
        enqueue_incident(
            outbox_repo,
            IncidentProvenance(
                incident_id=incident.incident_id,
                device_id=incident.device_id,
                attack_type=attack_type,
                evidence_hash=hash_payload(alert.reference),
                timestamp=alert.timestamp,
            ),
        )
        incident_for_key[(device_id, attack_type)] = incident.incident_id

    for outcome in outcomes:
        if outcome.index in keys:
            outcome.incident_id = incident_for_key[keys[outcome.index]]

    return AlertBatchResponse(
        source=request.source, outcomes=outcomes, incident_ids=list(incident_for_key.values())
    )
