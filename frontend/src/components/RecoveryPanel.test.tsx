import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace } from '../api/types'
import { RecoveryPanel } from './RecoveryPanel'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderPanel(traces: AgentTrace[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <RecoveryPanel incidentId="INC-1" traces={traces} />
    </QueryClientProvider>,
  )
}

const recoveryResult = {
  incident_id: 'INC-1',
  response_id: 'resp-1',
  containment_verified: true,
  residual_threats: [],
  recovery_succeeded: true,
  reinvestigation_required: false,
}

function recoveryTrace(overrides: Partial<AgentTrace>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'recovery_verification',
    input_payload: {},
    output_payload: recoveryResult,
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
    ...overrides,
  }
}

describe('RecoveryPanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('says recovery has not been verified when there is no recovery_verification trace', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    renderPanel([])

    expect(await screen.findByText(/Not yet verified/)).toBeInTheDocument()
    expect(screen.getByText(/Recovery Verification agent/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Submit recovery result' })).not.toBeInTheDocument()
  })

  it('shows the real recovery result and submits it, which refreshes the submitted list', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST' && url.includes('/recovery')) {
        return Promise.resolve(
          jsonResponse({
            incident_id: 'INC-1',
            device_id: 'ventilator-01',
            status: 'resolved',
            created_at: '2026-10-12T00:00:00Z',
            updated_at: '2026-10-12T02:00:00Z',
            chain_tx_id: null,
          }),
        )
      }
      if (url.includes('/recovery/INC-1')) {
        return Promise.resolve(jsonResponse([recoveryResult]))
      }
      return Promise.resolve(jsonResponse([]))
    })

    renderPanel([recoveryTrace({})])

    await waitFor(() => expect(screen.getAllByText('yes')).toHaveLength(2)) // containment verified + recovery succeeded
    const submitButton = screen.getByRole('button', { name: 'Submit recovery result' })
    await userEvent.click(submitButton)

    expect(await screen.findByText(/response resp-1: succeeded/)).toBeInTheDocument()
  })
})
