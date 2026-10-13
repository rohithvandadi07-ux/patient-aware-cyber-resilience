import { Link } from 'react-router-dom'
import { useDevices, useIncidents, useTelemetry } from '../api/queries'
import { latestReadingByDevice } from '../api/telemetryLatest'
import type { DeviceCriticality, Incident } from '../api/types'
import { Panel } from '../components/Panel'

/**
 * The IoMT Fleet view -- every real `DeviceState` (`GET /devices`) plus
 * each device's latest recorded telemetry (`GET /telemetry`, no
 * `device_id` filter, grouped client-side to the newest reading per
 * device -- see `telemetryLatest.ts`) and which incidents reference it
 * (`GET /incidents`, filtered by `device_id`). A device with no telemetry
 * recorded yet shows that plainly rather than a fabricated reading -- the
 * in-memory `TelemetryStore` only has data once a scenario has actually
 * run.
 */

const CRITICALITY_STYLES: Record<DeviceCriticality, string> = {
  low: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  medium: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  high: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
}

const OPERATIONAL_STATE_STYLES: Record<string, string> = {
  idle: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  active: 'bg-clinical-100 text-clinical-700 dark:bg-clinical-900 dark:text-clinical-300',
  alarm: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
  isolated: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  off: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

function formatReadings(readings: Record<string, number>): string {
  const entries = Object.entries(readings)
  if (entries.length === 0) return 'no fields recorded'
  return entries.map(([key, value]) => `${key}: ${value}`).join(', ')
}

function incidentsForDevice(incidents: Incident[], deviceId: string): Incident[] {
  return incidents.filter((incident) => incident.device_id === deviceId)
}

export function Fleet() {
  const devicesQuery = useDevices()
  const telemetryQuery = useTelemetry()
  const incidentsQuery = useIncidents()

  const isLoading = devicesQuery.isLoading || telemetryQuery.isLoading || incidentsQuery.isLoading
  const firstError = devicesQuery.error ?? telemetryQuery.error ?? incidentsQuery.error

  const devices = devicesQuery.data ?? []
  const incidents = incidentsQuery.data ?? []
  const latestByDevice = latestReadingByDevice(telemetryQuery.data ?? [])

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">IoMT Fleet</h1>

      {isLoading && <p className="text-sm text-gray-500">Loading fleet…</p>}
      {firstError && (
        <p className="text-sm text-danger-600" role="alert">
          Failed to load fleet data: {firstError instanceof Error ? firstError.message : 'unknown error'}
        </p>
      )}

      {!isLoading && !firstError && (
        <Panel title={`All devices (${devices.length})`}>
          {devices.length === 0 ? (
            <p className="text-sm text-gray-500 dark:text-gray-400">No devices registered.</p>
          ) : (
            <div className="space-y-3">
              {devices.map((device) => {
                const latest = latestByDevice.get(device.device_id)
                const deviceIncidents = incidentsForDevice(incidents, device.device_id)
                return (
                  <article
                    key={device.device_id}
                    className="rounded-md border border-gray-200 p-3 dark:border-gray-800"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{device.device_id}</h3>
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          {device.device_type.replaceAll('_', ' ')}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${CRITICALITY_STYLES[device.criticality]}`}
                        >
                          {device.criticality} criticality
                        </span>
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${OPERATIONAL_STATE_STYLES[device.operational_state] ?? CRITICALITY_STYLES.low}`}
                        >
                          {device.operational_state}
                        </span>
                        {device.patient_dependency && (
                          <span className="inline-flex items-center rounded-full bg-cyber-100 px-2.5 py-0.5 text-xs font-medium text-cyber-700 dark:bg-cyber-900 dark:text-cyber-300">
                            patient-dependent
                          </span>
                        )}
                      </div>
                    </div>

                    <dl className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                      <div>
                        <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Network state</dt>
                        <dd>{device.network_state}</dd>
                      </div>
                      <div>
                        <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Synthetic patient</dt>
                        <dd>{device.synthetic_patient_id ?? <span className="italic text-gray-400">none</span>}</dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Latest telemetry</dt>
                        <dd>
                          {latest ? (
                            <>
                              <span className="text-gray-500 dark:text-gray-400">
                                {formatTimestamp(latest.timestamp)} —{' '}
                              </span>
                              {formatReadings(latest.readings)}
                            </>
                          ) : (
                            <span className="text-gray-400 dark:text-gray-500">No telemetry recorded yet.</span>
                          )}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Incidents</dt>
                        <dd>
                          {deviceIncidents.length === 0 ? (
                            <span className="text-gray-400 dark:text-gray-500">none</span>
                          ) : (
                            <span className="flex flex-wrap gap-2">
                              {deviceIncidents.map((incident) => (
                                <Link
                                  key={incident.incident_id}
                                  to={`/incidents/${encodeURIComponent(incident.incident_id)}`}
                                  className="text-cyber-700 hover:underline dark:text-cyber-300"
                                >
                                  {incident.incident_id}
                                </Link>
                              ))}
                            </span>
                          )}
                        </dd>
                      </div>
                    </dl>
                  </article>
                )
              })}
            </div>
          )}
        </Panel>
      )}
    </div>
  )
}
