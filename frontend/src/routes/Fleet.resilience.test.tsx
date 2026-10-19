import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DeviceState } from '../api/types'
import { Fleet } from './Fleet'

function mockFetch(responses: Record<string, unknown>) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const path = url.replace(/^https?:\/\/[^/]+/, '')
      const body = path in responses ? responses[path] : []
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    }),
  )
}

function renderFleet() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Fleet />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const base: DeviceState = {
  device_id: 'ventilator-01',
  device_type: 'ventilator',
  criticality: 'high',
  patient_dependency: true,
  synthetic_patient_id: null,
  operational_state: 'active',
  network_state: 'connected',
}

describe('Fleet response state', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the seeded sessions, credential version, backup and standby', async () => {
    mockFetch({
      '/devices': [
        {
          ...base,
          active_sessions: ['a', 'b'],
          credential_version: 1,
          backup_available: true,
          backup_active: false,
          standby_unit_id: 'ventilator-01-standby',
          serving_unit: null,
        },
      ],
    })
    renderFleet()
    expect(await screen.findByTestId('resilience-ventilator-01')).toHaveTextContent(
      'sessions 2 · credential v1 · backup available · standby ventilator-01-standby',
    )
  })

  it('reflects the state after resilience actions have run', async () => {
    mockFetch({
      '/devices': [
        {
          ...base,
          active_sessions: [],
          credential_version: 2,
          backup_available: true,
          backup_active: true,
          standby_unit_id: 'ventilator-01-standby',
          serving_unit: 'ventilator-01-standby',
        },
      ],
    })
    renderFleet()
    expect(await screen.findByTestId('resilience-ventilator-01')).toHaveTextContent(
      'sessions 0 · credential v2 · backup active · standby serving ventilator-01-standby',
    )
  })

  it('falls back to neutral defaults when the backend sends no resilience fields', async () => {
    mockFetch({ '/devices': [base] })
    renderFleet()
    expect(await screen.findByTestId('resilience-ventilator-01')).toHaveTextContent(
      'sessions 0 · credential v1 · backup none · standby none',
    )
  })
})
