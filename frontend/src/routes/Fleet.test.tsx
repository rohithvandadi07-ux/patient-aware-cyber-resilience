import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DeviceState, Incident, TelemetryReading } from '../api/types'
import { Fleet } from './Fleet'

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
        <Fleet />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const device: DeviceState = {
  device_id: 'infusion-pump-02',
  device_type: 'infusion_pump',
  criticality: 'medium',
  patient_dependency: false,
  synthetic_patient_id: null,
  operational_state: 'active',
  network_state: 'connected',
}

const oldReading: TelemetryReading = {
  device_id: 'infusion-pump-02',
  timestamp: '2026-10-12T00:00:00Z',
  readings: { flow_rate: 12 },
}

const newReading: TelemetryReading = {
  device_id: 'infusion-pump-02',
  timestamp: '2026-10-12T01:00:00Z',
  readings: { flow_rate: 14 },
}

const incident: Incident = {
  incident_id: 'INC-9',
  device_id: 'infusion-pump-02',
  status: 'resolved',
  created_at: '2026-10-11T00:00:00Z',
  updated_at: '2026-10-11T01:00:00Z',
  chain_tx_id: 'tx-1',
}

describe('Fleet', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows an empty state when no devices are registered', async () => {
    mockFetchByPath({ '/devices': [], '/telemetry': [], '/incidents': [] })

    renderWithProviders()

    expect(await screen.findByText(/No devices registered/i)).toBeInTheDocument()
  })

  it('renders each device with its criticality, state, latest telemetry, and linked incidents', async () => {
    mockFetchByPath({
      '/devices': [device],
      '/telemetry': [oldReading, newReading],
      '/incidents': [incident],
    })

    renderWithProviders()

    expect(await screen.findByText('infusion-pump-02')).toBeInTheDocument()
    expect(screen.getByText('medium criticality')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    // The newer reading wins, not the older one.
    expect(screen.getByText(/flow_rate: 14/)).toBeInTheDocument()
    expect(screen.queryByText(/flow_rate: 12/)).not.toBeInTheDocument()

    const link = screen.getByRole('link', { name: 'INC-9' })
    expect(link).toHaveAttribute('href', '/incidents/INC-9')
  })

  it('shows "no telemetry recorded yet" for a device with no readings, never a fabricated one', async () => {
    mockFetchByPath({ '/devices': [device], '/telemetry': [], '/incidents': [] })

    renderWithProviders()

    expect(await screen.findByText('infusion-pump-02')).toBeInTheDocument()
    expect(screen.getByText(/No telemetry recorded yet/i)).toBeInTheDocument()
  })

  it('surfaces a failed load instead of hiding it', async () => {
    const mockFetch = vi.fn(() => Promise.resolve(new Response('internal server error', { status: 500 })))
    vi.stubGlobal('fetch', mockFetch)

    renderWithProviders()

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load fleet data/i)
  })
})
