import type { OutboxEntry } from './types'

/**
 * Real attack type per incident, read from each incident's own
 * `IncidentProvenance` outbox entry (`record_type === 'incident'`;
 * `app/schemas/blockchain.py`'s `IncidentProvenance.attack_type`,
 * `enqueue_incident`'s `provenance.model_dump(mode="json")` payload).
 * This is the one place an incident's attack type is recorded anywhere
 * the API exposes -- `Incident` itself (`app/schemas/incident.py`) has no
 * `attack_type` field (see `backend/app/api/incidents.py`'s own docstring:
 * "not stored on the `Incident` schema itself"). An incident whose
 * `incident` outbox entry hasn't been written yet (or was created outside
 * the `POST /incidents` / `/detections/run-scenario` paths that enqueue
 * one) is simply absent from the map, never assigned a guessed type.
 */
export function attackTypeByIncident(entries: OutboxEntry[]): Map<string, string> {
  const map = new Map<string, string>()

  for (const entry of entries) {
    if (entry.record_type !== 'incident') continue
    const payload = entry.payload as { incident_id?: string; attack_type?: string }
    if (payload.incident_id && payload.attack_type) {
      map.set(payload.incident_id, payload.attack_type)
    }
  }

  return map
}
