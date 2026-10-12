import { Link } from 'react-router-dom'
import { useIncidents, useRunScenarioMutation } from '../api/queries'
import { Panel } from '../components/Panel'
import { StatusBadge } from '../components/StatusBadge'

/** Formats an ISO timestamp for display, falling back to the raw string if
 * it isn't parseable -- never throws on unexpected backend data. */
function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

export function IncidentList() {
  const incidentsQuery = useIncidents()
  const runScenario = useRunScenarioMutation()

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Incidents</h1>
        <button
          type="button"
          onClick={() => runScenario.mutate()}
          disabled={runScenario.isPending}
          className="rounded-md bg-cyber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {runScenario.isPending ? 'Running scenario…' : 'Run Scenario'}
        </button>
      </div>

      {runScenario.isError && (
        <p className="text-sm text-danger-600" role="alert">
          Scenario run failed: {runScenario.error instanceof Error ? runScenario.error.message : 'unknown error'}
        </p>
      )}
      {runScenario.isSuccess && (
        <p className="text-sm text-clinical-700" role="status">
          Scenario produced {runScenario.data.length} detection event{runScenario.data.length === 1 ? '' : 's'}.
        </p>
      )}

      <Panel title="All incidents">
        {incidentsQuery.isLoading && <p className="text-sm text-gray-500">Loading incidents…</p>}
        {incidentsQuery.isError && (
          <p className="text-sm text-danger-600" role="alert">
            Failed to load incidents:{' '}
            {incidentsQuery.error instanceof Error ? incidentsQuery.error.message : 'unknown error'}
          </p>
        )}
        {incidentsQuery.isSuccess && incidentsQuery.data.length === 0 && (
          <p className="text-sm text-gray-500">
            No incidents yet. Run the scenario above to inject a detectable attack against the simulated devices.
          </p>
        )}
        {incidentsQuery.isSuccess && incidentsQuery.data.length > 0 && (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-gray-500 dark:border-gray-800 dark:text-gray-400">
                <th className="py-2 pr-4 font-medium">Incident</th>
                <th className="py-2 pr-4 font-medium">Device</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Updated</th>
                <th className="py-2 pr-4 font-medium">Chain tx</th>
              </tr>
            </thead>
            <tbody>
              {incidentsQuery.data.map((incident) => (
                <tr
                  key={incident.incident_id}
                  className="border-b border-gray-100 last:border-0 dark:border-gray-800/60"
                >
                  <td className="py-2 pr-4">
                    <Link
                      to={`/incidents/${encodeURIComponent(incident.incident_id)}`}
                      className="font-medium text-cyber-700 hover:underline dark:text-cyber-300"
                    >
                      {incident.incident_id}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">{incident.device_id}</td>
                  <td className="py-2 pr-4">
                    <StatusBadge status={incident.status} />
                  </td>
                  <td className="py-2 pr-4 text-gray-500 dark:text-gray-400">
                    {formatTimestamp(incident.updated_at)}
                  </td>
                  <td className="py-2 pr-4 text-gray-500 dark:text-gray-400">
                    {incident.chain_tx_id ?? <span className="italic">not yet committed</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
