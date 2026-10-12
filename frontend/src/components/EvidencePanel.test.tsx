import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AgentTrace } from '../api/types'
import { EvidencePanel } from './EvidencePanel'

const investigationReport = {
  incident_id: 'INC-1',
  evidence: ['unusual MQTT traffic spike from ventilator-01'],
  timeline: ['2026-10-12T00:00:00Z: first anomalous packet observed'],
  affected_devices: ['ventilator-01'],
  observations: ['traffic pattern matches known DoS signature'],
  confidence: 0.87,
}

function trace(overrides: Partial<AgentTrace>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'investigation',
    input_payload: {},
    output_payload: investigationReport,
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
    ...overrides,
  }
}

describe('EvidencePanel', () => {
  it('says not yet investigated when there is no investigation trace', () => {
    render(<EvidencePanel traces={[]} />)
    expect(screen.getByText('Not yet investigated.')).toBeInTheDocument()
  })

  it('ignores a failed investigation trace', () => {
    render(<EvidencePanel traces={[trace({ succeeded: false, output_payload: null, error: 'stalled' })]} />)
    expect(screen.getByText('Not yet investigated.')).toBeInTheDocument()
  })

  it('renders the real investigation report fields', () => {
    render(<EvidencePanel traces={[trace({})]} />)

    expect(screen.getByText('87%')).toBeInTheDocument()
    expect(screen.getByText('ventilator-01')).toBeInTheDocument()
    expect(screen.getByText(/unusual MQTT traffic spike/)).toBeInTheDocument()
    expect(screen.getByText(/first anomalous packet observed/)).toBeInTheDocument()
    expect(screen.getByText(/matches known DoS signature/)).toBeInTheDocument()
  })
})
