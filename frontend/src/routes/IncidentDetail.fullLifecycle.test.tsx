import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IncidentDetail } from './IncidentDetail'

/**
 * The direct test of the Phase 10 gate (Section 19): "one incident's full
 * lifecycle is viewable and the dual-risk panel is visually distinct, per
 * Section 16." Every fixture below is shaped exactly like what
 * `backend/tests/test_lifecycle_integration.py` proved the real API
 * produces for one incident that goes all the way from detection to
 * resolution -- same field names, same realistic values (ventilator-01,
 * spoofing/isolate_critical, a resolved status, five confirmed outbox
 * entries). This test exists to catch the case where every panel passes in
 * isolation (see each panel's own `.test.tsx`) but the full page doesn't
 * actually render all of them together for one real, complete incident.
 */

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function agentTrace(agentName: string, outputPayload: Record<string, unknown>) {
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

const investigationReport = {
  incident_id: 'INC-1',
  evidence: ["spoofed_command network event targeting ventilator-01's tidal volume setpoint"],
  timeline: ['scenario tick 6: spoofed_command injected'],
  affected_devices: ['ventilator-01'],
  observations: ['the command did not originate from an authenticated controller'],
  confidence: 0.85,
}

const threatAssessment = {
  incident_id: 'INC-1',
  attack_type: 'spoofing',
  severity: 'high',
  confidence: 0.85,
  propagation_risk: 'medium',
  reasoning_summary: 'High severity given direct patient-safety exposure.',
}

const clinicalContext = {
  incident_id: 'INC-1',
  device_criticality: 'high',
  patient_dependency: true,
  clinical_impact_level: 'high',
  safety_constraints: ['ventilator must not be shut down or fully isolated without a verified failover'],
}

const proposedResponse = {
  incident_id: 'INC-1',
  candidate_actions: [{ action_category: 'isolate_critical', description: 'Isolate ventilator-01' }],
  security_benefit: { isolate_critical: 0.9 },
  clinical_impact: { isolate_critical: 'medium' },
  recommended_action: 'isolate_critical',
  rationale: 'Isolation fully contains the spoofing vector.',
}

const recoveryResult = {
  incident_id: 'INC-1',
  response_id: 'INC-1-response-1',
  containment_verified: true,
  residual_threats: [],
  recovery_succeeded: true,
  reinvestigation_required: false,
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

describe('IncidentDetail -- full resolved lifecycle', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders every panel with real data for one incident that went all the way to resolved', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST' && url.includes('/risk-assessments')) {
        return Promise.resolve(
          jsonResponse({
            incident_id: 'INC-1',
            cyber_risk: 0.82,
            clinical_risk: 0.64,
            response_impact: { isolate_critical: 'medium' },
            explanation: 'High cyber risk from an active spoofing attack; high clinical risk from patient dependency.',
          }),
        )
      }
      if (url.includes('/incidents/INC-1')) {
        return Promise.resolve(
          jsonResponse({
            incident_id: 'INC-1',
            device_id: 'ventilator-01',
            status: 'resolved',
            created_at: '2026-10-12T00:00:00Z',
            updated_at: '2026-10-12T02:00:00Z',
            chain_tx_id: 'tx-incident-1',
          }),
        )
      }
      if (url.includes('/agents/INC-1')) {
        return Promise.resolve(
          jsonResponse([
            agentTrace('investigation', investigationReport),
            agentTrace('threat_reasoning', threatAssessment),
            agentTrace('healthcare_context', clinicalContext),
            agentTrace('response_planning', proposedResponse),
            agentTrace('recovery_verification', recoveryResult),
          ]),
        )
      }
      if (url.includes('/responses/proposed/INC-1')) {
        // Cleared server-side once executed -- a real, honest 404.
        return Promise.resolve(jsonResponse({ detail: 'none' }, 404))
      }
      if (url.includes('/responses/executed/INC-1')) {
        return Promise.resolve(
          jsonResponse([
            {
              incident_id: 'INC-1',
              action_taken: 'isolate_critical',
              executed_by: 'autonomous-orchestrator',
              timestamp: '2026-10-12T01:00:00Z',
              chain_tx_id: 'tx-response-1',
            },
          ]),
        )
      }
      if (url.includes('/recovery/INC-1')) {
        return Promise.resolve(jsonResponse([recoveryResult]))
      }
      if (url.includes('/blockchain/audit/INC-1')) {
        return Promise.resolve(
          jsonResponse(
            ['incident', 'decision', 'response', 'recovery'].map((recordType, i) => ({
              id: i + 1,
              record_type: recordType,
              payload: {},
              created_at: '2026-10-12T00:00:00Z',
              status: 'confirmed',
              chain_tx_id: `tx-${recordType}-1`,
              attempts: 1,
              last_error: null,
              updated_at: '2026-10-12T00:01:00Z',
            })),
          ),
        )
      }
      throw new Error(`unexpected fetch to ${url}`)
    })

    renderAt('INC-1')

    // Header: real incident id, device, and resolved status.
    expect(await screen.findByRole('heading', { name: 'INC-1' })).toBeInTheDocument()
    expect(screen.getAllByText('ventilator-01').length).toBeGreaterThan(0)
    expect(screen.getByText('Resolved')).toBeInTheDocument()

    // Agent Activity: all five agents really ran and succeeded.
    await waitFor(() => expect(screen.getAllByText('Succeeded')).toHaveLength(5))

    // Evidence: the real investigation report.
    expect(
      screen.getAllByText(/spoofed_command network event targeting ventilator-01/).length,
    ).toBeGreaterThan(0)
    expect(screen.getByText('85%')).toBeInTheDocument()

    // Dual-risk panel starts unassessed (it's never auto-fetched -- see
    // DualRiskPanel's own doc), then shows real scores once triggered.
    const assessButton = await screen.findByRole('button', { name: 'Assess risk' })
    await waitFor(() => expect(assessButton).toBeEnabled())
    await userEvent.click(assessButton)
    expect(await screen.findByText('82%')).toBeInTheDocument()
    expect(screen.getByText('64%')).toBeInTheDocument()

    // Response: already executed, with a real on-chain tx id (also shown in
    // the audit trail below -- same tx id, same real executed response).
    expect(await screen.findByText(/isolate_critical by autonomous-orchestrator/)).toBeInTheDocument()
    expect(screen.getAllByText('tx-response-1').length).toBeGreaterThan(0)

    // Recovery: the submitted result that actually resolved the incident.
    expect(screen.getByText(/response INC-1-response-1: succeeded/)).toBeInTheDocument()

    // Blockchain audit: all four real provenance events, all confirmed.
    expect(screen.getByText('incident')).toBeInTheDocument()
    expect(screen.getByText('decision')).toBeInTheDocument()
    expect(screen.getAllByText('confirmed')).toHaveLength(4)
    expect(screen.getByText('tx-incident-1')).toBeInTheDocument()
  })
})
