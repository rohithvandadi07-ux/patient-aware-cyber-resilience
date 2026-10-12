import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AgentTrace } from '../api/types'
import { AgentActivityPanel } from './AgentActivityPanel'

function trace(overrides: Partial<AgentTrace>): AgentTrace {
  return {
    incident_id: 'INC-1',
    agent_name: 'investigation',
    input_payload: { note: 'real input' },
    output_payload: { note: 'real output' },
    succeeded: true,
    recorded_at: '2026-10-12T00:00:00Z',
    error: null,
    ...overrides,
  }
}

describe('AgentActivityPanel', () => {
  it('shows every one of the five known agents as "Not run" when there are no traces at all', () => {
    render(<AgentActivityPanel traces={[]} />)

    expect(screen.getByText('Investigation agent')).toBeInTheDocument()
    expect(screen.getByText('Threat Reasoning agent')).toBeInTheDocument()
    expect(screen.getByText('Clinical Context agent')).toBeInTheDocument()
    expect(screen.getByText('Response Planning agent')).toBeInTheDocument()
    expect(screen.getByText('Recovery Verification agent')).toBeInTheDocument()
    expect(screen.getAllByText('Not run')).toHaveLength(5)
  })

  it('shows a succeeded agent with its real timestamp and leaves the others as not run', () => {
    render(
      <AgentActivityPanel
        traces={[trace({ agent_name: 'investigation', recorded_at: '2026-10-12T03:04:00Z' })]}
      />,
    )

    expect(screen.getByText('Succeeded')).toBeInTheDocument()
    expect(screen.getAllByText('Not run')).toHaveLength(4)
  })

  it('shows a failed agent with its real error message, never hidden or softened', () => {
    render(
      <AgentActivityPanel
        traces={[
          trace({
            agent_name: 'threat_reasoning',
            succeeded: false,
            output_payload: null,
            error: 'failed to produce a valid structured output after retry',
          }),
        ]}
      />,
    )

    expect(screen.getByText('Failed')).toBeInTheDocument()
    expect(screen.getByText(/failed to produce a valid structured output after retry/)).toBeInTheDocument()
  })

  it('notes how many times an agent ran when it has more than one trace, and uses the most recent outcome', () => {
    render(
      <AgentActivityPanel
        traces={[
          trace({ agent_name: 'investigation', recorded_at: '2026-10-12T00:00:00Z', succeeded: false, error: 'first attempt failed' }),
          trace({ agent_name: 'investigation', recorded_at: '2026-10-12T01:00:00Z', succeeded: true }),
        ]}
      />,
    )

    expect(screen.getByText('ran 2×')).toBeInTheDocument()
    expect(screen.getByText('Succeeded')).toBeInTheDocument()
  })
})
