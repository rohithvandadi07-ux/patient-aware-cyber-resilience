import { useAllAuditEntries, useAllExecutedResponses, useAllRecoveryResults, useIncidents } from '../api/queries'
import { attackTypeByIncident } from '../api/incidentProvenance'
import { HorizontalBarList, type BarRow } from '../components/HorizontalBarList'
import { Panel } from '../components/Panel'
import { StatTile } from '../components/StatTile'

/**
 * Historical Incidents + Analytics -- aggregates over every real record
 * the backend has actually produced so far, never a second analytics
 * endpoint:
 *  - attack type counts come from each resolved incident's own
 *    `IncidentProvenance` outbox entry (`incidentProvenance.ts`) -- the
 *    only place an incident's attack type is recorded at all, since
 *    `Incident` itself has no such field.
 *  - average time-to-resolution is `updated_at - created_at` for every
 *    incident whose real `status` is `resolved`.
 *  - response-action distribution counts `GET /responses/executed`
 *    entries whose incident has resolved.
 *  - recovery success rate reads every submitted `GET /recovery` result
 *    (not narrowed to currently-resolved incidents -- a `reopened`
 *    incident's earlier failed attempt is still a real recovery attempt
 *    that happened, and dropping it would overstate the success rate).
 */

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return 'unknown'
  const minutes = Math.round(ms / 60000)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  const remMinutes = minutes % 60
  return remMinutes === 0 ? `${hours}h` : `${hours}h ${remMinutes}m`
}

function humanizeKey(value: string): string {
  const spaced = value.replaceAll('_', ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

export function Analytics() {
  const incidentsQuery = useIncidents()
  const auditQuery = useAllAuditEntries()
  const executedQuery = useAllExecutedResponses()
  const recoveryQuery = useAllRecoveryResults()

  const isLoading = incidentsQuery.isLoading || auditQuery.isLoading || executedQuery.isLoading || recoveryQuery.isLoading
  const firstError = incidentsQuery.error ?? auditQuery.error ?? executedQuery.error ?? recoveryQuery.error

  const incidents = incidentsQuery.data ?? []
  const resolvedIncidents = incidents.filter((incident) => incident.status === 'resolved')
  const resolvedIds = new Set(resolvedIncidents.map((incident) => incident.incident_id))

  const attackTypeMap = attackTypeByIncident(auditQuery.data ?? [])
  const attackTypeCounts = new Map<string, number>()
  for (const incident of resolvedIncidents) {
    const attackType = attackTypeMap.get(incident.incident_id)
    if (!attackType) continue
    attackTypeCounts.set(attackType, (attackTypeCounts.get(attackType) ?? 0) + 1)
  }
  const attackTypeRows: BarRow[] = [...attackTypeCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({ key: type, label: humanizeKey(type), value: count }))

  const resolutionDurationsMs = resolvedIncidents.map(
    (incident) => new Date(incident.updated_at).getTime() - new Date(incident.created_at).getTime(),
  )
  const avgResolutionMs =
    resolutionDurationsMs.length > 0
      ? resolutionDurationsMs.reduce((sum, ms) => sum + ms, 0) / resolutionDurationsMs.length
      : null

  const executedForResolved = (executedQuery.data ?? []).filter((response) => resolvedIds.has(response.incident_id))
  const actionCounts = new Map<string, number>()
  for (const response of executedForResolved) {
    actionCounts.set(response.action_taken, (actionCounts.get(response.action_taken) ?? 0) + 1)
  }
  const actionRows: BarRow[] = [...actionCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([action, count]) => ({ key: action, label: humanizeKey(action), value: count }))

  const recoveryResults = recoveryQuery.data ?? []
  const succeededCount = recoveryResults.filter((result) => result.recovery_succeeded).length
  const recoverySuccessRate =
    recoveryResults.length > 0 ? Math.round((succeededCount / recoveryResults.length) * 100) : null

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Historical Incidents &amp; Analytics</h1>

      {isLoading && <p className="text-sm text-gray-500">Loading historical data…</p>}
      {firstError && (
        <p className="text-sm text-danger-600" role="alert">
          Failed to load analytics data: {firstError instanceof Error ? firstError.message : 'unknown error'}
        </p>
      )}

      {!isLoading && !firstError && (
        <>
          <div className="grid gap-4 sm:grid-cols-2">
            <StatTile
              label="Resolved incidents"
              value={resolvedIncidents.length}
              sublabel={`of ${incidents.length} total`}
            />
            <StatTile
              label="Avg. time to resolution"
              value={avgResolutionMs !== null ? formatDuration(avgResolutionMs) : undefined}
              empty="No resolved incidents yet"
              sublabel={avgResolutionMs !== null ? `across ${resolvedIncidents.length} resolved incident${resolvedIncidents.length === 1 ? '' : 's'}` : undefined}
            />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Panel title="Resolved incidents by attack type">
              <HorizontalBarList
                rows={attackTypeRows}
                emptyMessage="No resolved incident has a recorded attack type yet."
              />
            </Panel>
            <Panel title="Response action distribution">
              <HorizontalBarList
                rows={actionRows}
                emptyMessage="No response has been executed for a resolved incident yet."
              />
            </Panel>
          </div>

          <Panel title="Recovery success rate">
            {recoverySuccessRate !== null ? (
              <div className="space-y-2">
                <div className="flex items-baseline justify-between">
                  <span className="text-sm text-gray-600 dark:text-gray-300">
                    {succeededCount} of {recoveryResults.length} submitted recovery result
                    {recoveryResults.length === 1 ? '' : 's'} succeeded
                  </span>
                  <span className="text-2xl font-semibold tabular-nums">{recoverySuccessRate}%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-gray-100 dark:bg-gray-800">
                  <div
                    className="h-2 rounded-full bg-severity-good"
                    style={{ width: `${recoverySuccessRate}%` }}
                    role="img"
                    aria-label={`${recoverySuccessRate}% of submitted recovery results succeeded`}
                  />
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400">No recovery result has been submitted yet.</p>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
