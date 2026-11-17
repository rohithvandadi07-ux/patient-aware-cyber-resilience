import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { PolicyAnchorView } from '../api/types'
import { Policy } from './Policy'

const HASH = '4621df98a69096a7e58080e7627d08f12f9ca8b046284a17c37f011914ec5f72'

function policyBody(anchor: PolicyAnchorView) {
  return {
    name: 'pacr-default-policy',
    version: 1,
    policy_hash: HASH,
    source: 'bundled:policy.default.yaml',
    safety_floor: ['floor rule A', 'floor rule B'],
    rules: [
      {
        id: 'patient_dependent_severe_action',
        when: { patient_dependency: true, action_in: ['shutdown', 'isolate_critical'] },
        requires_human_approval: true,
        rationale: 'r1',
      },
      {
        id: 'autonomous_low_impact',
        when: { impact_at_most: 'low' },
        requires_human_approval: false,
        rationale: 'r2',
      },
    ],
    anchor,
  }
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function mockApi(routes: Record<string, () => unknown>): string[] {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const path = url.replace(/^https?:\/\/[^/]+/, '')
      const key = `${init?.method ?? 'GET'} ${path}`
      calls.push(key)
      const handler = routes[key]
      return Promise.resolve(jsonResponse(handler ? handler() : []))
    }),
  )
  return calls
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Policy />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('Policy page', () => {
  it('shows the hash, the safety floor and the rules in order with their outcomes', async () => {
    mockApi({
      'GET /policy': () => policyBody({ state: 'not_queued', chain_tx_id: null, last_error: null }),
    })
    renderPage()
    expect(await screen.findByText(HASH)).toBeTruthy()
    expect(screen.getByText('floor rule A')).toBeTruthy()
    const rows = screen.getAllByRole('row')
    expect(rows[1].textContent).toContain('patient_dependent_severe_action')
    expect(rows[2].textContent).toContain('autonomous_low_impact')
    expect(screen.getAllByText('Human approval')).toHaveLength(1)
    expect(screen.getAllByText('Autonomous')).toHaveLength(1)
    expect(screen.getByText(/Not queued yet/)).toBeTruthy()
  })

  it('shows the transaction id once the policy is anchored', async () => {
    mockApi({
      'GET /policy': () => policyBody({ state: 'confirmed', chain_tx_id: 'mock-tx-13', last_error: null }),
    })
    renderPage()
    expect(await screen.findByText('Anchored on ledger')).toBeTruthy()
    expect(screen.getByText('mock-tx-13')).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('commits pending entries from the pending state and refreshes the policy', async () => {
    const calls = mockApi({
      'GET /policy': () => policyBody({ state: 'pending', chain_tx_id: null, last_error: null }),
    })
    renderPage()
    expect(await screen.findByText(/waiting to be committed/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /commit pending entries/i }))
    await waitFor(() => expect(calls).toContain('POST /blockchain/audit/process'))
    await waitFor(() => expect(calls.filter((c) => c === 'GET /policy').length).toBeGreaterThan(1))
  })

  it('shows the error when anchoring failed and offers no button', async () => {
    mockApi({
      'GET /policy': () =>
        policyBody({ state: 'failed', chain_tx_id: null, last_error: 'ledger unreachable' }),
    })
    renderPage()
    expect(await screen.findByText('Anchoring failed')).toBeTruthy()
    expect(screen.getByText('ledger unreachable')).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('says so when the policy cannot be loaded', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('boom', { status: 500 }))),
    )
    renderPage()
    expect(await screen.findByRole('alert')).toBeTruthy()
  })
})
