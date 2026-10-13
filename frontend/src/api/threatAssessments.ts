import type { AgentTrace, ThreatAssessment } from './types'

/**
 * Real `ThreatAssessment`s, one per incident, derived from each incident's
 * most recent successful `threat_reasoning` agent trace -- the same
 * "a successful trace's `output_payload` IS the real agent's own
 * `model_dump(mode='json')`" reasoning `riskAssessmentFromTraces.ts`
 * documents, just applied across every incident at once instead of one at
 * a time. An incident with no successful `threat_reasoning` trace yet is
 * simply absent from the map -- never assigned a guessed severity, since
 * `Incident` itself (`app/schemas/incident.py`) carries no severity field
 * of its own.
 */
export function latestThreatAssessmentsByIncident(traces: AgentTrace[]): Map<string, ThreatAssessment> {
  const byIncident = new Map<string, ThreatAssessment>()
  const recordedAt = new Map<string, number>()

  for (const trace of traces) {
    if (trace.agent_name !== 'threat_reasoning' || !trace.succeeded || trace.output_payload === null) continue
    const t = new Date(trace.recorded_at).getTime()
    const latestSoFar = recordedAt.get(trace.incident_id)
    if (latestSoFar === undefined || t >= latestSoFar) {
      recordedAt.set(trace.incident_id, t)
      byIncident.set(trace.incident_id, trace.output_payload as unknown as ThreatAssessment)
    }
  }

  return byIncident
}
