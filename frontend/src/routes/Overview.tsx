import { Link } from 'react-router-dom'
import { useAllAgentTraces, useDevices, useIncidents } from '../api/queries'
import { latestThreatAssessmentsByIncident } from '../api/threatAssessments'
import type { ImpactLevel, Incident, OperationalState } from '../api/types'
import { HorizontalBarList, type BarRow } from '../components/HorizontalBarList'
import { Panel } from '../components/Panel'
import { SeverityBadge } from '../components/SeverityBadge'
import { SEVERITY_DOT } from '../components/severityStyles'
import { StatTile } from '../components/StatTile'
import { StatusBadge } from '../components/StatusBadge'

/**
 * The Executive Overview -- the dashboard's new landing route. Every
 * number here is read off the same three real endpoints the rest of the
 * app already uses (`GET /incidents`, `GET /devices`, `GET /agents`),
 * never a second summary endpoint that could drift from the per-incident
 * views. In particular, incident severity is not a field `Incident` has
 * (`app/schemas/incident.py`) -- it is read from each incident's own most
 * recent `threat_reasoning` agent trace (`threatAssessments.ts`), the same
 * real data `IncidentDetail`'s dual-risk flow depends on. An incident with
 * no successful `threat_reasoning` trace yet is counted as "not yet
 * assessed," never guessed into a severity bucket.
 */

const RESOLVED_STATUSES = new Set<Incident['status']>(['resolved'])

const SEVERITY_ORDER: ImpactLevel[] = ['critical', 'high', 'medium', 'low']

const SEVERITY_ROW_LABEL: Record<ImpactLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

const OPERATIONAL_STATE_LABEL: Record<OperationalState, string> = {
  idle: 'Idle',
  active: 'Active',
  alarm: 'Alarm',
  isolated: 'Isolated',
  off: 'Off',
}

/** Devices in `alarm` are the real, device-level analog of "under attack"
 * -- the simulator's own state, not an inference this view adds. */
const OPERATIONAL_STATE_BAR_CLASS: Record<OperationalState, string> = {
  idle: 'bg-severity-good',
  active: 'bg-severity-good',
  alarm: 'bg-severity-critical',
  isolated: 'bg-severity-warning',
  off: 'bg-severity-unknown',
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

export function Overview() {
  const incidentsQuery = useIncidents()
  const devicesQuery = useDevices()
  const agentTracesQuery = useAllAgentTraces()

  const isLoading = incidentsQuery.isLoading || devicesQuery.isLoading || agentTracesQuery.isLoading
  const firstError = incidentsQuery.error ?? devicesQuery.error ?? agentTracesQuery.error

  const incidents = incidentsQuery.data ?? []
  const devices = devicesQuery.data ?? []
  const severityByIncident = latestThreatAssessmentsByIncident(agentTracesQuery.data ?? [])

  const activeIncidents = incidents.filter((incident) => !RESOLVED_STATUSES.has(incident.status))
  const awaitingApproval = incidents.filter((incident) => incident.status === 'awaiting_approval').length
  const stalled = incidents.filter((incident) => incident.status.endsWith('_stalled')).length

  const severityCounts = new Map<ImpactLevel, number>()
  let unassessedActive = 0
  for (const incident of activeIncidents) {
    const assessment = severityByIncident.get(incident.incident_id)
    if (!assessment) {
      unassessedActive += 1
      continue
    }
    severityCounts.set(assessment.severity, (severityCounts.get(assessment.severity) ?? 0) + 1)
  }

  const severityRows: BarRow[] = SEVERITY_ORDER.filter((level) => (severityCounts.get(level) ?? 0) > 0).map(
    (level) => ({
      key: level,
      label: SEVERITY_ROW_LABEL[level],
      value: severityCounts.get(level) ?? 0,
      barClassName: SEVERITY_DOT[level],
    }),
  )
  if (unassessedActive > 0) {
    severityRows.push({ key: 'unassessed', label: 'Not yet assessed', value: unassessedActive, barClassName: 'bg-severity-unknown' })
  }

  const highestActiveSeverity = SEVERITY_ORDER.find((level) => (severityCounts.get(level) ?? 0) > 0) ?? null

  const deviceStateCounts = new Map<OperationalState, number>()
  for (const device of devices) {
    deviceStateCounts.set(device.operational_state, (deviceStateCounts.get(device.operational_state) ?? 0) + 1)
  }
  const deviceRows: BarRow[] = (Object.keys(OPERATIONAL_STATE_LABEL) as OperationalState[])
    .filter((state) => (deviceStateCounts.get(state) ?? 0) > 0)
    .map((state) => ({
      key: state,
      label: OPERATIONAL_STATE_LABEL[state],
      value: deviceStateCounts.get(state) ?? 0,
      barClassName: OPERATIONAL_STATE_BAR_CLASS[state],
    }))
  const devicesInAlarm = deviceStateCounts.get('alarm') ?? 0

  const recentIncidents = [...incidents]
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
    .slice(0, 8)

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Executive Overview</h1>

      {isLoading && <p className="text-sm text-gray-500">Loading fleet and incident data…</p>}
      {firstError && (
        <p className="text-sm text-danger-600" role="alert">
          Failed to load overview data: {firstError instanceof Error ? firstError.message : 'unknown error'}
        </p>
      )}

      {!isLoading && !firstError && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile label="Active incidents" value={activeIncidents.length} sublabel={`${incidents.length} total`} />
            <StatTile
              label="Awaiting approval"
              value={awaitingApproval}
              accent={awaitingApproval > 0 ? 'border-amber-500' : undefined}
            />
            <StatTile
              label="Stalled"
              value={stalled}
              accent={stalled > 0 ? 'border-danger-500' : undefined}
              sublabel="An agent stage failed and needs attention"
            />
            <StatTile
              label="Devices in alarm"
              value={devicesInAlarm}
              sublabel={`of ${devices.length} devices`}
              accent={devicesInAlarm > 0 ? 'border-danger-500' : undefined}
            />
          </div>

          <Panel title="Aggregate threat level">
            {highestActiveSeverity ? (
              <div className="flex items-center gap-3">
                <SeverityBadge severity={highestActiveSeverity} />
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  highest severity among {activeIncidents.length - unassessedActive} assessed active incident
                  {activeIncidents.length - unassessedActive === 1 ? '' : 's'}
                  {unassessedActive > 0 &&
                    ` (${unassessedActive} active incident${unassessedActive === 1 ? '' : 's'} not yet assessed)`}
                </span>
              </div>
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {activeIncidents.length === 0
                  ? 'No active incidents right now.'
                  : `No threat assessment has completed yet for any of the ${activeIncidents.length} active incident${activeIncidents.length === 1 ? '' : 's'}.`}
              </p>
            )}
          </Panel>

          <div className="grid gap-4 md:grid-cols-2">
            <Panel title="Active incidents by severity">
              <HorizontalBarList
                rows={severityRows}
                emptyMessage="No active incidents to break down by severity."
              />
            </Panel>
            <Panel title="Device fleet health">
              <HorizontalBarList rows={deviceRows} emptyMessage="No devices registered." />
            </Panel>
          </div>

          <Panel title="Recent incident feed">
            {recentIncidents.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No incidents yet. Run a scenario from the Incidents view to inject a detectable attack.
              </p>
            ) : (
              <ul className="divide-y divide-gray-100 dark:divide-gray-800/60">
                {recentIncidents.map((incident) => (
                  <li key={incident.incident_id} className="flex items-center justify-between py-2 text-sm">
                    <div className="flex items-center gap-3">
                      <Link
                        to={`/incidents/${encodeURIComponent(incident.incident_id)}`}
                        className="font-medium text-cyber-700 hover:underline dark:text-cyber-300"
                      >
                        {incident.incident_id}
                      </Link>
                      <span className="text-gray-500 dark:text-gray-400">{incident.device_id}</span>
                      <SeverityBadge severity={severityByIncident.get(incident.incident_id)?.severity ?? null} />
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-gray-400 dark:text-gray-500">{formatTimestamp(incident.updated_at)}</span>
                      <StatusBadge status={incident.status} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
