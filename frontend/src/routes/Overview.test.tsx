import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace, DeviceState, Incident } from '../api/types'
import { Overview } from './Overview'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetchByPath(responses: Record<string, unknown>) {
  const mockFetch = vi.fn((url: string) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    if (path in responses) return Promise.resolve(jsonResponse(responses[path]))
    return Promise.resolve(jsonResponse([]))
  })
  vi.stubGlobal('fetch', mockFetch)
  return mockFetch
}

function renderWithProviders() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Overview />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const incident: Incident = {
  incident_id: 'INC-1',
  device_id: 'ventilator-01',
  status: 'investigating',
  created_at: '2026-10-12T00:00:00Z',
  updated_at: '2026-10-12T00:05:00Z',
  chain_tx_id: null,
}

const device: DeviceState = {
  device_id: 'ventilator-01',
  device_type: 'ventilator',
  criticality: 'high',
  patient_dependency: true,
  synthetic_patient_id: 'synthetic-patient-1',
  operational_state: 'alarm',
  network_state: 'connected',
}

const threatTrace: AgentTrace = {
  incident_id: 'INC-1',
  agent_name: 'threat_reasoning',
  input_payload: {},
  output_payload: {
    incident_id: 'INC-1',
    attack_type: 'dos',
    severity: 'critical',
    confidence: 0.9,
    propagation_risk: 'high',
    reasoning_summary: 'Sustained DoS traffic against a patient-dependent ventilator.',
  },
  succeeded: true,
  recorded_at: '2026-10-12T00:02:00Z',
  error: null,
}

describe('Overview', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows an honest empty state when nothing has happened yet', async () => {
    mockFetchByPath({ '/incidents': [], '/devices': [], '/agents': [] })

    renderWithProviders()

    expect(await screen.findByText(/No active incidents right now/i)).toBeInTheDocument()
    expect(screen.getByText(/No incidents yet/i)).toBeInTheDocument()
    expect(screen.getByText(/No devices registered/i)).toBeInTheDocument()
  })

  it('derives active-incident severity from the real threat_reasoning agent trace, not a guess', async () => {
    mockFetchByPath({
      '/incidents': [incident],
      '/devices': [device],
      '/agents': [threatTrace],
    })

    renderWithProviders()

    expect(await screen.findByRole('link', { name: 'INC-1' })).toHaveAttribute('href', '/incidents/INC-1')
    // The severity breakdown and the aggregate threat level both surface the
    // real derived "Critical" bucket.
    expect(screen.getAllByText('Critical').length).toBeGreaterThan(0)
    expect(screen.getByText(/Devices in alarm/i)).toBeInTheDocument()
  })

  it('counts an active incident with no threat assessment yet as "not yet assessed", never a guessed severity', async () => {
    mockFetchByPath({
      '/incidents': [incident],
      '/devices': [device],
      '/agents': [], // no threat_reasoning trace recorded
    })

    renderWithProviders()

    await screen.findByRole('link', { name: 'INC-1' })
    expect(screen.getByText(/No threat assessment has completed yet/i)).toBeInTheDocument()
    // Both the severity-breakdown bar row and the recent-feed badge render
    // the same honest "not yet assessed" label.
    expect(screen.getAllByText('Not yet assessed').length).toBeGreaterThan(0)
  })

  it('surfaces a failed load instead of hiding it', async () => {
    const mockFetch = vi.fn(() => Promise.resolve(new Response('internal server error', { status: 500 })))
    vi.stubGlobal('fetch', mockFetch)

    renderWithProviders()

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load overview data/i)
  })
})
