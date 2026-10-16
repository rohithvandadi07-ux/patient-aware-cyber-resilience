import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AgentTrace, RiskScore } from '../api/types'
import { ResponsePanel } from './ResponsePanel'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetchByUrl(handlers: { match: string; response: () => Response }[]) {
  const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
  mockFetch.mockImplementation((url: string) => {
    const handler = handlers.find((h) => url.includes(h.match))
    if (!handler) throw new Error(`unexpected fetch to ${url}`)
    return Promise.resolve(handler.response())
  })
}

function renderPanel(traces: AgentTrace[], riskScore: RiskScore | null) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ResponsePanel incidentId="INC-1" traces={traces} riskScore={riskScore} />
    </QueryClientProvider>,
  )
}

const clinicalContext = {
  incident_id: 'INC-1',
  device_criticality: 'high',
  patient_dependency: true,
  clinical_impact_level: 'high',
  safety_constraints: [],
}

const proposedResponse = {
  incident_id: 'INC-1',
  candidate_actions: [{ action_category: 'isolate_critical', description: 'isolate' }],
  security_benefit: {},
  clinical_impact: {},
  recommended_action: 'isolate_critical',
  rationale: 'real rationale',
}

const riskScore: RiskScore = {
  incident_id: 'INC-1',
  cyber_risk: 0.8,
  clinical_risk: 0.5,
  response_impact: {},
  explanation: 'real explanation',
}

function contextAndPlanningTraces(): AgentTrace[] {
  return [
    {
      incident_id: 'INC-1',
      agent_name: 'healthcare_context',
      input_payload: {},
      output_payload: clinicalContext,
      succeeded: true,
      recorded_at: '2026-10-12T00:00:00Z',
      error: null,
    },
    {
      incident_id: 'INC-1',
      agent_name: 'response_planning',
      input_payload: {},
      output_payload: proposedResponse,
      succeeded: true,
      recorded_at: '2026-10-12T00:00:00Z',
      error: null,
    },
  ]
}

describe('ResponsePanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('disables Propose response and explains what is missing when there is no risk score or traces', async () => {
    mockFetchByUrl([
      { match: '/responses/proposed/INC-1', response: () => jsonResponse({ detail: 'none' }, 404) },
      { match: '/responses/executed/INC-1', response: () => jsonResponse([]) },
    ])

    renderPanel([], null)

    expect(await screen.findByText(/No response proposed yet/)).toBeInTheDocument()
    expect(screen.getByText(/Waiting on: a risk assessment for this incident/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Propose response' })).toBeDisabled()
  })

  it('proposes a response built from real traces and a real risk score', async () => {
    // Stateful: the policy decision only exists once the POST below actually
    // creates it, so the GET-by-id must flip from 404 to 200 for real,
    // rather than a static mock that would mask a broken invalidation.
    let decision: unknown = null
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockImplementation((url: string, init?: RequestInit) => {
      if (url.includes('/responses/executed/INC-1')) return Promise.resolve(jsonResponse([]))
      if (init?.method === 'POST' && url.includes('/responses/proposed')) {
        decision = {
          incident_id: 'INC-1',
          chosen_action: 'isolate_critical',
          requires_human_approval: false,
          policy_rule_id: 'rule-1',
          rationale: 'autonomous: low enough combined risk',
        }
        return Promise.resolve(jsonResponse(decision, 201))
      }
      if (url.includes('/responses/proposed/INC-1')) {
        return Promise.resolve(decision ? jsonResponse(decision) : jsonResponse({ detail: 'none' }, 404))
      }
      throw new Error(`unexpected fetch to ${url}`)
    })

    renderPanel(contextAndPlanningTraces(), riskScore)

    const proposeButton = await screen.findByRole('button', { name: 'Propose response' })
    expect(proposeButton).toBeEnabled()
    await userEvent.click(proposeButton)

    expect(await screen.findByText('isolate_critical')).toBeInTheDocument()
    expect(screen.getByText('rule-1')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Execute (no approval required)' })).toBeInTheDocument()
  })

  it('lists the ranked alternatives the Policy Engine considered, with their routing', async () => {
    mockFetchByUrl([
      {
        match: '/responses/proposed/INC-1',
        response: () =>
          jsonResponse({
            incident_id: 'INC-1',
            chosen_action: 'shutdown',
            requires_human_approval: true,
            policy_rule_id: 'patient_dependent_severe_action',
            rationale: 'needs a human',
            alternatives: [
              {
                action: 'block_traffic',
                response_impact: 'low',
                requires_human_approval: false,
                policy_rule_id: 'autonomous_low_impact',
                security_benefit: 0.5,
              },
              {
                action: 'isolate_critical',
                response_impact: 'high',
                requires_human_approval: true,
                policy_rule_id: 'patient_dependent_severe_action',
                security_benefit: null,
              },
            ],
          }),
      },
      { match: '/responses/executed/INC-1', response: () => jsonResponse([]) },
    ])

    renderPanel([], null)

    expect(await screen.findByText('Alternatives considered')).toBeInTheDocument()
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('block_traffic')
    expect(rows[1]).toHaveTextContent('autonomous')
    expect(rows[1]).toHaveTextContent('0.50')
    expect(rows[2]).toHaveTextContent('isolate_critical')
    expect(rows[2]).toHaveTextContent('needs approval')
    expect(rows[2]).toHaveTextContent('—')
  })

  it('shows no alternatives section when the decision has none', async () => {
    mockFetchByUrl([
      {
        match: '/responses/proposed/INC-1',
        response: () =>
          jsonResponse({
            incident_id: 'INC-1',
            chosen_action: 'block_traffic',
            requires_human_approval: false,
            policy_rule_id: 'autonomous_low_impact',
            rationale: 'ok',
          }),
      },
      { match: '/responses/executed/INC-1', response: () => jsonResponse([]) },
    ])

    renderPanel([], null)

    expect(await screen.findByText('block_traffic')).toBeInTheDocument()
    expect(screen.queryByText('Alternatives considered')).not.toBeInTheDocument()
  })

  it('shows an approval form when the policy decision requires human approval, and disables execute until an approver is entered', async () => {
    mockFetchByUrl([
      {
        match: '/responses/proposed/INC-1',
        response: () =>
          jsonResponse({
            incident_id: 'INC-1',
            chosen_action: 'shutdown',
            requires_human_approval: true,
            policy_rule_id: 'rule-critical',
            rationale: 'shutdown on a patient-dependent device requires a human',
          }),
      },
      { match: '/responses/executed/INC-1', response: () => jsonResponse([]) },
    ])

    renderPanel([], null)

    expect(await screen.findByText(/Requires human approval/)).toBeInTheDocument()
    const approveButton = screen.getByRole('button', { name: 'Approve & execute' })
    expect(approveButton).toBeDisabled()

    await userEvent.type(screen.getByPlaceholderText('Approver identity'), 'dr.smith')
    expect(approveButton).toBeEnabled()
  })

  it('renders executed responses with an honest "not yet committed" marker when chain_tx_id is null', async () => {
    mockFetchByUrl([
      { match: '/responses/proposed/INC-1', response: () => jsonResponse({ detail: 'none' }, 404) },
      {
        match: '/responses/executed/INC-1',
        response: () =>
          jsonResponse([
            {
              incident_id: 'INC-1',
              action_taken: 'isolate_critical',
              executed_by: 'autonomous-orchestrator',
              timestamp: '2026-10-12T01:00:00Z',
              chain_tx_id: null,
            },
          ]),
      },
    ])

    renderPanel([], null)

    await waitFor(() => expect(screen.getByText(/isolate_critical by autonomous-orchestrator/)).toBeInTheDocument())
    expect(screen.getByText('not yet committed')).toBeInTheDocument()
  })
})
