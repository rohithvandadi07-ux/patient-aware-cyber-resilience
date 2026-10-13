import { Link } from 'react-router-dom'
import { useAllAgentTraces, useEvents, useIncidents } from '../api/queries'
import { latestThreatAssessmentsByIncident } from '../api/threatAssessments'
import type { ImpactLevel, Incident } from '../api/types'
import { HorizontalBarList, type BarRow } from '../components/HorizontalBarList'
import { Panel } from '../components/Panel'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusBadge } from '../components/StatusBadge'

/**
 * A chronological monitoring view, deliberately not another table of rows
 * (`IncidentList.tsx` already is that) -- a vertical timeline merging two
 * real event streams: `GET /incidents` (each incident's own
 * `created_at`/`updated_at`, plus its severity read the same way
 * `Overview.tsx` reads it, off the latest `threat_reasoning` agent trace)
 * and `GET /events` (every recorded `NetworkEvent`, unfiltered). Nothing
 * here is synthesized -- an incident contributes at most two real
 * timestamps it actually has, and an event contributes its own recorded
 * timestamp and `is_attack_injection` flag, never an inferred severity of
 * its own (events have no severity field; only incidents, via their
 * threat assessment, do).
 */

type TimelineItem =
  | {
      kind: 'incident-detected' | 'incident-updated'
      timestamp: string
      incidentId: string
      deviceId: string
      severity: ImpactLevel | null
      status: Incident['status']
    }
  | { kind: 'event'; timestamp: string; deviceId: string; eventType: string; source: string; isAttackInjection: boolean }

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

function dayBucket(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'unknown date'
  return date.toISOString().slice(0, 10)
}

export function ThreatMonitor() {
  const incidentsQuery = useIncidents()
  const eventsQuery = useEvents()
  const agentTracesQuery = useAllAgentTraces()

  const isLoading = incidentsQuery.isLoading || eventsQuery.isLoading || agentTracesQuery.isLoading
  const firstError = incidentsQuery.error ?? eventsQuery.error ?? agentTracesQuery.error

  const incidents = incidentsQuery.data ?? []
  const events = eventsQuery.data ?? []
  const severityByIncident = latestThreatAssessmentsByIncident(agentTracesQuery.data ?? [])

  const items: TimelineItem[] = []

  for (const incident of incidents) {
    const severity = severityByIncident.get(incident.incident_id)?.severity ?? null
    items.push({
      kind: 'incident-detected',
      timestamp: incident.created_at,
      incidentId: incident.incident_id,
      deviceId: incident.device_id,
      severity,
      status: incident.status,
    })
    if (incident.updated_at !== incident.created_at) {
      items.push({
        kind: 'incident-updated',
        timestamp: incident.updated_at,
        incidentId: incident.incident_id,
        deviceId: incident.device_id,
        severity,
        status: incident.status,
      })
    }
  }

  for (const event of events) {
    items.push({
      kind: 'event',
      timestamp: event.timestamp,
      deviceId: event.device_id,
      eventType: event.event_type,
      source: event.source,
      isAttackInjection: event.is_attack_injection,
    })
  }

  const sorted = [...items].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  const shown = sorted.slice(0, 60)

  const perDay = new Map<string, number>()
  for (const event of events) {
    const bucket = dayBucket(event.timestamp)
    perDay.set(bucket, (perDay.get(bucket) ?? 0) + 1)
  }
  const dayRows: BarRow[] = [...perDay.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([day, count]) => ({ key: day, label: day, value: count }))

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Threat Monitor</h1>

      {isLoading && <p className="text-sm text-gray-500">Loading events and incidents…</p>}
      {firstError && (
        <p className="text-sm text-danger-600" role="alert">
          Failed to load threat monitor data: {firstError instanceof Error ? firstError.message : 'unknown error'}
        </p>
      )}

      {!isLoading && !firstError && (
        <>
          <Panel title="Network events per day">
            <HorizontalBarList rows={dayRows} emptyMessage="No network events recorded yet." />
          </Panel>

          <Panel title={`Timeline (${shown.length} of ${sorted.length} events)`}>
            {shown.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No incidents or network events recorded yet. Run a scenario from the Incidents view.
              </p>
            ) : (
              <ol className="relative space-y-4 border-l border-gray-200 pl-4 dark:border-gray-800">
                {shown.map((item, i) => (
                  <li key={i} className="relative">
                    <span
                      className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full ring-2 ring-white dark:ring-gray-900 ${
                        item.kind === 'event'
                          ? item.isAttackInjection
                            ? 'bg-severity-critical'
                            : 'bg-severity-unknown'
                          : item.severity === 'critical'
                            ? 'bg-severity-critical'
                            : item.severity === 'high'
                              ? 'bg-severity-serious'
                              : item.severity === 'medium'
                                ? 'bg-severity-warning'
                                : item.severity === 'low'
                                  ? 'bg-severity-good'
                                  : 'bg-severity-unknown'
                      }`}
                      aria-hidden="true"
                    />
                    <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                      {item.kind === 'event' ? (
                        <span>
                          <span className="font-medium">{item.deviceId}</span> — {item.eventType} from {item.source}
                          {item.isAttackInjection && (
                            <span className="ml-2 rounded-full bg-severity-critical/10 px-2 py-0.5 text-xs font-medium text-danger-700 dark:text-danger-500">
                              attack injection
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <Link
                            to={`/incidents/${encodeURIComponent(item.incidentId)}`}
                            className="font-medium text-cyber-700 hover:underline dark:text-cyber-300"
                          >
                            {item.incidentId}
                          </Link>
                          <span className="text-gray-500 dark:text-gray-400">
                            {item.kind === 'incident-detected' ? 'detected on' : 'updated on'} {item.deviceId}
                          </span>
                          <StatusBadge status={item.status} />
                          <SeverityBadge severity={item.severity} />
                        </span>
                      )}
                      <span className="text-xs text-gray-400 dark:text-gray-500">{formatTimestamp(item.timestamp)}</span>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
