import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Incident } from '../api/types'
import { IncidentList } from './IncidentList'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderWithProviders() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <IncidentList />
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

describe('IncidentList', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows an empty state when there are no incidents yet', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    renderWithProviders()

    expect(await screen.findByText(/No incidents yet/i)).toBeInTheDocument()
  })

  it('renders each incident as a row linking to its detail page', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([incident]))

    renderWithProviders()

    const link = await screen.findByRole('link', { name: 'INC-1' })
    expect(link).toHaveAttribute('href', '/incidents/INC-1')
    expect(screen.getByText('ventilator-01')).toBeInTheDocument()
    expect(screen.getByText('Investigating')).toBeInTheDocument()
    expect(screen.getByText('not yet committed')).toBeInTheDocument()
  })

  it('surfaces a failed incident list load instead of hiding it', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(new Response('internal server error', { status: 500 }))

    renderWithProviders()

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load incidents/i)
  })

  it('runs the scenario and reports how many detections it produced', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([])) // initial incident list
    mockFetch.mockResolvedValueOnce(
      jsonResponse([
        {
          device_id: 'ventilator-01',
          attack_type: 'dos',
          confidence: 0.9,
          severity_hint: 'high',
          timestamp: '2026-10-12T00:00:00Z',
          evidence_ref: 'evidence-1',
        },
      ]),
    ) // run-scenario response
    mockFetch.mockResolvedValueOnce(jsonResponse([incident])) // incidents refetch after invalidation

    renderWithProviders()
    await screen.findByText(/No incidents yet/i)

    await userEvent.click(screen.getByRole('button', { name: 'Run Scenario' }))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('1 detection event'))
  })
})
