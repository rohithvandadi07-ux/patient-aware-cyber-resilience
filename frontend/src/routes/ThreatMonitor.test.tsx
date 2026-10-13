import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace, Incident, NetworkEvent } from '../api/types'
import { ThreatMonitor } from './ThreatMonitor'

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
        <ThreatMonitor />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const incident: Incident = {
  incident_id: 'INC-5',
  device_id: 'ecg-monitor-03',
  status: 'resolved',
  created_at: '2026-10-12T00:00:00Z',
  updated_at: '2026-10-12T00:30:00Z',
  chain_tx_id: 'tx-9',
}

const attackEvent: NetworkEvent = {
  device_id: 'ecg-monitor-03',
  timestamp: '2026-10-12T00:10:00Z',
  event_type: 'mqtt_flood',
  source: 'simulated-attacker',
  payload: {},
  is_attack_injection: true,
}

const threatTrace: AgentTrace = {
  incident_id: 'INC-5',
  agent_name: 'threat_reasoning',
  input_payload: {},
  output_payload: {
    incident_id: 'INC-5',
    attack_type: 'mqtt_based',
    severity: 'high',
    confidence: 0.8,
    propagation_risk: 'medium',
    reasoning_summary: 'MQTT flood against the ECG monitor.',
  },
  succeeded: true,
  recorded_at: '2026-10-12T00:15:00Z',
  error: null,
}

describe('ThreatMonitor', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows an empty state when nothing has been recorded yet', async () => {
    mockFetchByPath({ '/incidents': [], '/events': [], '/agents': [] })

    renderWithProviders()

    expect(await screen.findByText(/No incidents or network events recorded yet/i)).toBeInTheDocument()
    expect(screen.getByText(/No network events recorded yet/i)).toBeInTheDocument()
  })

  it('merges incidents and events into one chronological, severity-colored timeline', async () => {
    mockFetchByPath({
      '/incidents': [incident],
      '/events': [attackEvent],
      '/agents': [threatTrace],
    })

    renderWithProviders()

    // The incident contributes two timeline markers (detected + updated),
    // each a real link to the same incident.
    const links = await screen.findAllByRole('link', { name: 'INC-5' })
    expect(links.length).toBe(2)
    for (const link of links) expect(link).toHaveAttribute('href', '/incidents/INC-5')
    expect(screen.getByText(/mqtt_flood from simulated-attacker/)).toBeInTheDocument()
    expect(screen.getByText('attack injection')).toBeInTheDocument()
    // Two incident timestamps (created + updated, since they differ) plus
    // one event timestamp.
    expect(screen.getByText(/Timeline \(3 of 3 events\)/)).toBeInTheDocument()
  })

  it('surfaces a failed load instead of hiding it', async () => {
    const mockFetch = vi.fn(() => Promise.resolve(new Response('internal server error', { status: 500 })))
    vi.stubGlobal('fetch', mockFetch)

    renderWithProviders()

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load threat monitor data/i)
  })
})
