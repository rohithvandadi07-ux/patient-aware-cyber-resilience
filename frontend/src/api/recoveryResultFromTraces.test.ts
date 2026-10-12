import { describe, expect, it } from 'vitest'
import { deriveRecoveryResult } from './recoveryResultFromTraces'
import type { AgentTrace } from './types'

const recoveryResult = {
  incident_id: 'INC-1',
  response_id: 'resp-1',
  containment_verified: true,
  residual_threats: [],
  recovery_succeeded: true,
  reinvestigation_required: false,
}

function trace(overrides: Partial<AgentTrace>): AgentTrace {
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

describe('deriveRecoveryResult', () => {
  it('says recovery verification is missing when there is no such trace', () => {
    const result = deriveRecoveryResult([])
    expect(result.result).toBeNull()
    expect(result.missingSteps).toEqual(['Recovery Verification agent'])
  })

  it('ignores a failed recovery_verification trace', () => {
    const result = deriveRecoveryResult([trace({ succeeded: false, output_payload: null, error: 'stalled' })])
    expect(result.result).toBeNull()
    expect(result.missingSteps).toEqual(['Recovery Verification agent'])
  })

  it('returns the real recovery result verbatim from a successful trace', () => {
    const result = deriveRecoveryResult([trace({})])
    expect(result.missingSteps).toEqual([])
    expect(result.result).toEqual(recoveryResult)
  })
})
