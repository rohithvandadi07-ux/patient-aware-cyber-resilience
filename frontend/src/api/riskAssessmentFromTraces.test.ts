import { describe, expect, it } from 'vitest'
import { deriveRiskAssessmentRequest } from './riskAssessmentFromTraces'
import type { AgentTrace } from './types'

function trace(overrides: Partial<AgentTrace>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'threat_reasoning',
    input_payload: {},
    output_payload: {},
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
    ...overrides,
  }
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

describe('deriveRiskAssessmentRequest', () => {
  it('reports all three steps missing when there are no traces at all', () => {
    const result = deriveRiskAssessmentRequest([])
    expect(result.request).toBeNull()
    expect(result.missingSteps).toEqual(['threat_reasoning', 'healthcare_context', 'response_planning'])
  })

  it('reports only the missing steps when some traces exist', () => {
    const result = deriveRiskAssessmentRequest([
      trace({ agent_name: 'threat_reasoning', output_payload: threatAssessment }),
    ])
    expect(result.request).toBeNull()
    expect(result.missingSteps).toEqual(['healthcare_context', 'response_planning'])
  })

  it('ignores a failed trace for a required agent -- it is not real usable output', () => {
    const result = deriveRiskAssessmentRequest([
      trace({ agent_name: 'threat_reasoning', output_payload: threatAssessment }),
      trace({ agent_name: 'healthcare_context', output_payload: clinicalContext }),
      trace({ agent_name: 'response_planning', succeeded: false, output_payload: null, error: 'LLM failure' }),
    ])
    expect(result.request).toBeNull()
    expect(result.missingSteps).toEqual(['response_planning'])
  })

  it('builds a real request from the three successful traces, verbatim', () => {
    const result = deriveRiskAssessmentRequest([
      trace({ agent_name: 'threat_reasoning', output_payload: threatAssessment }),
      trace({ agent_name: 'healthcare_context', output_payload: clinicalContext }),
      trace({ agent_name: 'response_planning', output_payload: proposedResponse }),
    ])
    expect(result.missingSteps).toEqual([])
    expect(result.request).toEqual({
      threat: threatAssessment,
      context: clinicalContext,
      candidate_responses: proposedResponse.candidate_actions,
    })
  })
})
