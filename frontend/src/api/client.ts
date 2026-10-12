/**
 * Typed client over the backend's 12 resource routers (`backend/app/api/`,
 * Phase 9). One function per endpoint, named after what it does rather than
 * its HTTP verb+path, so a caller reads `getIncident(id)` rather than
 * `request('GET', \`/incidents/${id}\`)`.
 *
 * `API_BASE_URL` defaults to the backend's own default dev port
 * (`Settings.api_port`, `backend/app/core/config.py`) and is overridable via
 * `VITE_API_BASE_URL` for any other deployment target.
 */

import type {
  AgentTrace,
  DetectionEvent,
  DeviceState,
  ExecuteResponseRequest,
  ExecutedResponse,
  HealthStatus,
  Incident,
  IncidentCreateRequest,
  NetworkEvent,
  OutboxEntry,
  OutboxStatus,
  PolicyDecision,
  ProposeResponseRequest,
  RecoveryResult,
  RiskAssessmentRequest,
  RiskScore,
  TelemetryReading,
} from './types'

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

/** Thrown for any non-2xx response. `detail` is FastAPI's own
 * `HTTPException` body shape (`{"detail": "..."}`) when the backend sent
 * one, so a caller can show the backend's real reason rather than a bare
 * status code. */
export class ApiError extends Error {
  readonly status: number
  readonly detail: unknown

  constructor(status: number, detail: unknown) {
    super(typeof detail === 'string' ? detail : `request failed with status ${status}`)
    this.status = status
    this.detail = detail
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })

  if (!response.ok) {
    // Read the body as text exactly once -- a Response's body stream can
    // only be consumed once, so `.json()` after a failed `.json()` (or vice
    // versa) throws "body stream already read," not a usable fallback.
    const rawBody = await response.text()
    let detail: unknown = rawBody
    try {
      const parsed = JSON.parse(rawBody) as { detail?: unknown }
      if (parsed && typeof parsed === 'object' && 'detail' in parsed) {
        detail = parsed.detail
      }
    } catch {
      // Not JSON -- the raw text is already the fallback `detail` above.
    }
    throw new ApiError(response.status, detail)
  }

  // 204 (none of this API's routes use it yet, but a future one might)
  // would have no body to parse.
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

function query(params: Record<string, string | undefined>): string {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined) as [string, string][]
  if (entries.length === 0) return ''
  return `?${new URLSearchParams(entries).toString()}`
}

// --- /health ---

export const getHealth = (): Promise<HealthStatus> => request('/health')

// --- /devices ---

export const listDevices = (): Promise<DeviceState[]> => request('/devices')

export const getDevice = (deviceId: string): Promise<DeviceState> =>
  request(`/devices/${encodeURIComponent(deviceId)}`)

// --- /telemetry ---

export const listTelemetry = (deviceId?: string): Promise<TelemetryReading[]> =>
  request(`/telemetry${query({ device_id: deviceId })}`)

// --- /events ---

export const listEvents = (deviceId?: string): Promise<NetworkEvent[]> =>
  request(`/events${query({ device_id: deviceId })}`)

// --- /incidents ---

export const listIncidents = (): Promise<Incident[]> => request('/incidents')

export const getIncident = (incidentId: string): Promise<Incident> =>
  request(`/incidents/${encodeURIComponent(incidentId)}`)

export const createIncident = (body: IncidentCreateRequest): Promise<Incident> =>
  request('/incidents', { method: 'POST', body: JSON.stringify(body) })

// --- /detections ---

export const runScenario = (): Promise<DetectionEvent[]> =>
  request('/detections/run-scenario', { method: 'POST' })

// --- /risk-assessments ---

export const calculateRisk = (body: RiskAssessmentRequest): Promise<RiskScore> =>
  request('/risk-assessments', { method: 'POST', body: JSON.stringify(body) })

// --- /agents ---

export const listAgentTraces = (params?: { incidentId?: string; agentName?: string }): Promise<AgentTrace[]> =>
  request(`/agents${query({ incident_id: params?.incidentId, agent_name: params?.agentName })}`)

export const listAgentTracesForIncident = (incidentId: string): Promise<AgentTrace[]> =>
  request(`/agents/${encodeURIComponent(incidentId)}`)

// --- /responses/proposed, /responses/executed ---

export const proposeResponse = (body: ProposeResponseRequest): Promise<PolicyDecision> =>
  request('/responses/proposed', { method: 'POST', body: JSON.stringify(body) })

export const listProposedResponses = (): Promise<PolicyDecision[]> => request('/responses/proposed')

export const getProposedResponse = (incidentId: string): Promise<PolicyDecision> =>
  request(`/responses/proposed/${encodeURIComponent(incidentId)}`)

export const executeResponse = (body: ExecuteResponseRequest): Promise<ExecutedResponse> =>
  request('/responses/executed', { method: 'POST', body: JSON.stringify(body) })

export const listExecutedResponses = (): Promise<ExecutedResponse[]> => request('/responses/executed')

export const listExecutedResponsesForIncident = (incidentId: string): Promise<ExecutedResponse[]> =>
  request(`/responses/executed/${encodeURIComponent(incidentId)}`)

// --- /recovery ---

export const processRecoveryResult = (body: RecoveryResult): Promise<Incident> =>
  request('/recovery', { method: 'POST', body: JSON.stringify(body) })

export const listRecoveryResults = (): Promise<RecoveryResult[]> => request('/recovery')

export const listRecoveryResultsForIncident = (incidentId: string): Promise<RecoveryResult[]> =>
  request(`/recovery/${encodeURIComponent(incidentId)}`)

// --- /blockchain/audit ---

export const listAuditEntries = (params?: {
  incidentId?: string
  status?: OutboxStatus
}): Promise<OutboxEntry[]> =>
  request(`/blockchain/audit${query({ incident_id: params?.incidentId, status: params?.status })}`)

export const getAuditTrailForIncident = (incidentId: string): Promise<OutboxEntry[]> =>
  request(`/blockchain/audit/${encodeURIComponent(incidentId)}`)

export const processPendingOutboxEntries = (): Promise<OutboxEntry[]> =>
  request('/blockchain/audit/process', { method: 'POST' })
