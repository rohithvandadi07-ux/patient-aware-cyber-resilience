import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  API_BASE_URL,
  createIncident,
  getDevice,
  getHealth,
  listAuditEntries,
  listTelemetry,
} from './client'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('api client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('getHealth calls GET /health and returns the parsed body', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'ok', service: 'backend' }))

    const result = await getHealth()

    expect(mockFetch).toHaveBeenCalledWith(`${API_BASE_URL}/health`, expect.objectContaining({}))
    expect(result).toEqual({ status: 'ok', service: 'backend' })
  })

  it('getDevice path-encodes the device id', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse({ device_id: 'ventilator 01' }))

    await getDevice('ventilator 01')

    expect(mockFetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/devices/ventilator%2001`,
      expect.anything(),
    )
  })

  it('listTelemetry omits the query string when no device_id is given', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    await listTelemetry()

    expect(mockFetch).toHaveBeenCalledWith(`${API_BASE_URL}/telemetry`, expect.anything())
  })

  it('listTelemetry includes device_id as a query parameter when given', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    await listTelemetry('ventilator-01')

    expect(mockFetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/telemetry?device_id=ventilator-01`,
      expect.anything(),
    )
  })

  it('listAuditEntries combines incident_id and status filters', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    await listAuditEntries({ incidentId: 'INC-1', status: 'pending' })

    const calledUrl = mockFetch.mock.calls[0][0] as string
    expect(calledUrl).toContain('incident_id=INC-1')
    expect(calledUrl).toContain('status=pending')
  })

  it('createIncident POSTs a JSON-serialized body', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse({ incident_id: 'INC-1' }))

    const body = {
      incident_id: 'INC-1',
      device_id: 'ventilator-01',
      attack_type: 'mitm_injection' as const,
      evidence_ref: 'evidence-1',
      timestamp: '2026-10-12T00:00:00Z',
    }
    await createIncident(body)

    expect(mockFetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/incidents`,
      expect.objectContaining({ method: 'POST', body: JSON.stringify(body) }),
    )
  })

  it('throws ApiError with the backend detail message on a non-2xx response', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse({ detail: "Incident 'INC-1' not found" }, 404))

    await expect(getDevice('does-not-exist')).rejects.toSatisfy((error: unknown) => {
      return error instanceof ApiError && error.status === 404 && error.detail === "Incident 'INC-1' not found"
    })
  })

  it('throws ApiError with the raw text when the error body is not JSON', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(new Response('internal server error', { status: 500 }))

    await expect(getHealth()).rejects.toSatisfy((error: unknown) => {
      return error instanceof ApiError && error.status === 500
    })
  })
})
