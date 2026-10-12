import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace, Incident } from '../api/types'
import { IncidentDetail } from './IncidentDetail'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderAt(incidentId: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/incidents/${incidentId}`]}>
        <Routes>
          <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const incident: Incident = {
  incident_id: 'INC-1',
  device_id: 'ventilator-01',
  status: 'awaiting_approval',
  created_at: '2026-10-12T00:00:00Z',
  updated_at: '2026-10-12T00:05:00Z',
  chain_tx_id: 'tx-abc',
}

const threatAssessment = {
  incident_id: 'INC-1',
  attack_type: 'dos',
  severity: 'high',
  confidence: 0.9,
  propagation_risk: 'medium',
  reasoning_summary: 'real summary',
}

const clinicalContext = {
  incident_id: 'INC-1',
  device_criticality: 'high',
  patient_dependency: true,
  clinical_impact_level: 'high',
  safety_constraints: ['do not shut down without failover'],
}

const proposedResponse = {
  incident_id: 'INC-1',
  candidate_actions: [{ action_category: 'isolate_critical', description: 'isolate the device' }],
  security_benefit: {},
  clinical_impact: {},
  recommended_action: 'isolate_critical',
  rationale: 'real rationale',
}

function traceFor(agentName: string, outputPayload: Record<string, unknown>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: agentName,
    input_payload: {},
    output_payload: outputPayload,
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
  }
}

/** Routes each mocked fetch call by URL so the test doesn't depend on which
 * of the incident/agent-traces queries happens to fire first. */
function mockFetchByUrl(handlers: { match: string; response: () => Response }[]) {
  const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
  mockFetch.mockImplementation((url: string) => {
    const handler = handlers.find((h) => url.includes(h.match))
    if (!handler) throw new Error(`unexpected fetch to ${url}`)
    return Promise.resolve(handler.response())
  })
}

describe('IncidentDetail', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('loads the incident by id from the route param and shows its status', async () => {
    mockFetchByUrl([
      { match: '/incidents/INC-1', response: () => jsonResponse(incident) },
      { match: '/agents/INC-1', response: () => jsonResponse([]) },
    ])

    renderAt('INC-1')

    expect(await screen.findByRole('heading', { name: 'INC-1' })).toBeInTheDocument()
    expect(screen.getByText('ventilator-01')).toBeInTheDocument()
    expect(screen.getByText('Awaiting approval')).toBeInTheDocument()
  })

  it('surfaces a load failure instead of showing a blank panel', async () => {
    mockFetchByUrl([
      { match: '/incidents/INC-404', response: () => jsonResponse({ detail: "Incident 'INC-404' not found" }, 404) },
      { match: '/agents/INC-404', response: () => jsonResponse([]) },
    ])

    renderAt('INC-404')

    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load incident INC-404/i)
  })

  it('shows the dual-risk panel as not-yet-assessed and names the missing agent steps when no traces exist', async () => {
    mockFetchByUrl([
      { match: '/incidents/INC-1', response: () => jsonResponse(incident) },
      { match: '/agents/INC-1', response: () => jsonResponse([]) },
    ])

    renderAt('INC-1')

    expect(await screen.findAllByText(/Not yet assessed/)).toHaveLength(2) // cyber panel + clinical panel
    expect(
      screen.getAllByText(/Threat Reasoning agent, Clinical Context agent, Response Planning agent/),
    ).toHaveLength(2)
    expect(screen.getByRole('button', { name: 'Assess risk' })).toBeDisabled()
    expect(screen.getAllByText('Not run')).toHaveLength(5) // Agent Activity panel, all five agents
  })

  it('assesses risk from real agent traces and renders the resulting dual-risk scores', async () => {
    mockFetchByUrl([
      { match: '/incidents/INC-1', response: () => jsonResponse(incident) },
      {
        match: '/agents/INC-1',
        response: () =>
          jsonResponse([
            traceFor('threat_reasoning', threatAssessment),
            traceFor('healthcare_context', clinicalContext),
            traceFor('response_planning', proposedResponse),
          ]),
      },
      {
        match: '/risk-assessments',
        response: () =>
          jsonResponse({
            incident_id: 'INC-1',
            cyber_risk: 0.82,
            clinical_risk: 0.64,
            response_impact: { isolate_critical: 'high' },
            explanation: 'High cyber risk from an active DoS attack; high clinical risk from patient dependency.',
          }),
      },
    ])

    renderAt('INC-1')

    const assessButton = await screen.findByRole('button', { name: 'Assess risk' })
    await waitFor(() => expect(assessButton).toBeEnabled())

    // Three agents have real traces; the other two (investigation,
    // recovery_verification) genuinely never ran for this incident.
    expect(screen.getAllByText('Succeeded')).toHaveLength(3)
    expect(screen.getAllByText('Not run')).toHaveLength(2)

    await userEvent.click(assessButton)

    expect(await screen.findByText('82%')).toBeInTheDocument()
    expect(screen.getByText('64%')).toBeInTheDocument()
    expect(screen.getByText(/High cyber risk from an active DoS attack/)).toBeInTheDocument()
    expect(screen.getByText('isolate_critical')).toBeInTheDocument()
  })
})
