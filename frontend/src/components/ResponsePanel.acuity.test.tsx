import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace } from '../api/types'
import { ResponsePanel } from './ResponsePanel'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetchByPath(responses: Record<string, unknown>) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const path = url.replace(/^https?:\/\/[^/]+/, '')
      return Promise.resolve(jsonResponse(path in responses ? responses[path] : []))
    }),
  )
}

function renderPanel(traces: AgentTrace[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ResponsePanel incidentId="INC-1" traces={traces} riskScore={null} />
    </QueryClientProvider>,
  )
}

const decision = {
  incident_id: 'INC-1',
  chosen_action: 'block_traffic',
  requires_human_approval: true,
  policy_rule_id: 'approval_high_acuity_patient',
  rationale: 'Human approval required: the connected patient is currently HIGH acuity.',
  alternatives: [],
}

function trace(output: Record<string, unknown>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'healthcare_context',
    input_payload: {},
    output_payload: output,
    succeeded: true,
    recorded_at: '2026-10-19T08:00:00Z',
    error: null,
  }
}

describe('ResponsePanel connected patient', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the patient acuity and NEWS2 recorded in the healthcare context trace', async () => {
    mockFetchByPath({ '/responses/proposed/INC-1': decision })
    renderPanel([trace({ patient_acuity: 'high', news2_score: 8 })])

    expect(await screen.findByTestId('connected-patient')).toHaveTextContent(
      'Connected patient: high acuity (NEWS2 8)',
    )
  })

  it('shows nothing about a patient when the trace has none', async () => {
    mockFetchByPath({ '/responses/proposed/INC-1': decision })
    renderPanel([trace({ patient_acuity: null, news2_score: null })])

    expect(await screen.findByText(/Chosen action/)).toBeInTheDocument()
    expect(screen.queryByTestId('connected-patient')).not.toBeInTheDocument()
  })
})
