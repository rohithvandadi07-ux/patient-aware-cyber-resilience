import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ExecutedResponse, Incident, OutboxEntry, RecoveryResult } from '../api/types'
import { Analytics } from './Analytics'

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
        <Analytics />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const resolvedIncident: Incident = {
  incident_id: 'INC-RESOLVED-1',
  device_id: 'ventilator-01',
  status: 'resolved',
  created_at: '2026-10-12T00:00:00Z',
  updated_at: '2026-10-12T00:30:00Z',
  chain_tx_id: 'tx-1',
}

const incidentOutboxEntry: OutboxEntry = {
  id: 1,
  record_type: 'incident',
  payload: {
    incident_id: 'INC-RESOLVED-1',
    device_id: 'ventilator-01',
    attack_type: 'dos',
    evidence_hash: 'hash-1',
    timestamp: '2026-10-12T00:00:00Z',
  },
  created_at: '2026-10-12T00:00:00Z',
  status: 'confirmed',
  chain_tx_id: 'tx-1',
  attempts: 1,
  last_error: null,
  updated_at: '2026-10-12T00:01:00Z',
}

const executedResponse: ExecutedResponse = {
  incident_id: 'INC-RESOLVED-1',
  action_taken: 'isolate_non_critical',
  executed_by: 'policy-engine',
  timestamp: '2026-10-12T00:10:00Z',
  chain_tx_id: 'tx-2',
}

const recoveryResult: RecoveryResult = {
  incident_id: 'INC-RESOLVED-1',
  response_id: 'resp-1',
  containment_verified: true,
  residual_threats: [],
  recovery_succeeded: true,
  reinvestigation_required: false,
}

describe('Analytics', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows honest empty states when there is no historical data yet', async () => {
    mockFetchByPath({ '/incidents': [], '/blockchain/audit': [], '/responses/executed': [], '/recovery': [] })

    renderWithProviders()

    expect(await screen.findByText(/No resolved incidents yet/i)).toBeInTheDocument()
    expect(screen.getByText(/No resolved incident has a recorded attack type yet/i)).toBeInTheDocument()
    expect(screen.getByText(/No response has been executed for a resolved incident yet/i)).toBeInTheDocument()
    expect(screen.getByText(/No recovery result has been submitted yet/i)).toBeInTheDocument()
  })

  it('aggregates real resolved-incident data: attack type, resolution time, actions, and recovery rate', async () => {
    mockFetchByPath({
      '/incidents': [resolvedIncident],
      '/blockchain/audit': [incidentOutboxEntry],
      '/responses/executed': [executedResponse],
      '/recovery': [recoveryResult],
    })

    renderWithProviders()

    expect(await screen.findByText('Dos')).toBeInTheDocument() // attack type, humanized from the real outbox payload
    expect(screen.getByText('30m')).toBeInTheDocument() // avg time to resolution
    expect(screen.getByText('Isolate non critical')).toBeInTheDocument() // response action distribution
    expect(screen.getByText('100%')).toBeInTheDocument() // recovery success rate
    expect(screen.getByText(/1 of 1 submitted recovery result/)).toBeInTheDocument()
  })

  it('surfaces a failed load instead of hiding it', async () => {
    const mockFetch = vi.fn(() => Promise.resolve(new Response('internal server error', { status: 500 })))
    vi.stubGlobal('fetch', mockFetch)

    renderWithProviders()

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load analytics data/i)
  })
})
