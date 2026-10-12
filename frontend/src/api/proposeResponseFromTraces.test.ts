import { describe, expect, it } from 'vitest'
import { deriveProposeResponseRequest } from './proposeResponseFromTraces'
import type { AgentTrace, RiskScore } from './types'

function trace(overrides: Partial<AgentTrace>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'healthcare_context',
    input_payload: {},
    output_payload: {},
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
    ...overrides,
  }
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
  security_benefit: { isolate_critical: 0.8 },
  clinical_impact: { isolate_critical: 'medium' },
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

describe('deriveProposeResponseRequest', () => {
  it('reports everything missing when there is no risk score and no traces', () => {
    const result = deriveProposeResponseRequest([], null)
    expect(result.request).toBeNull()
    expect(result.missingSteps).toEqual([
      'a risk assessment for this incident',
      'Clinical Context agent',
      'Response Planning agent',
    ])
  })

  it('reports only the risk score as missing once both agent traces exist', () => {
    const result = deriveProposeResponseRequest(
      [
        trace({ agent_name: 'healthcare_context', output_payload: clinicalContext }),
        trace({ agent_name: 'response_planning', output_payload: proposedResponse }),
      ],
      null,
    )
    expect(result.request).toBeNull()
    expect(result.missingSteps).toEqual(['a risk assessment for this incident'])
  })

  it('builds a real request from the risk score plus the two real agent traces', () => {
    const result = deriveProposeResponseRequest(
      [
        trace({ agent_name: 'healthcare_context', output_payload: clinicalContext }),
        trace({ agent_name: 'response_planning', output_payload: proposedResponse }),
      ],
      riskScore,
    )
    expect(result.missingSteps).toEqual([])
    expect(result.request).toEqual({
      risk_score: riskScore,
      proposed_response: proposedResponse,
      context: clinicalContext,
    })
  })
})
