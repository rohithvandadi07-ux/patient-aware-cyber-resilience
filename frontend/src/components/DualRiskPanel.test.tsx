import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { RiskScore } from '../api/types'
import { DualRiskPanel } from './DualRiskPanel'

describe('DualRiskPanel', () => {
  it('renders an honest not-assessed state for both risk panels and the decision panel when there is no score', () => {
    render(<DualRiskPanel riskScore={null} missingSteps={['Threat Reasoning agent']} />)

    expect(screen.getAllByText(/Not yet assessed/)).toHaveLength(2)
    expect(screen.getAllByText(/Waiting on real agent output for:/)).toHaveLength(2)
    expect(screen.getAllByText('Threat Reasoning agent')).toHaveLength(2)
    expect(screen.getByText(/No decision context yet/)).toBeInTheDocument()
  })

  it('renders both risk scores as equal-weight panels plus the decision panel when a real score is given', () => {
    const riskScore: RiskScore = {
      incident_id: 'INC-1',
      cyber_risk: 0.75,
      clinical_risk: 0.4,
      response_impact: { isolate_critical: 'high', block_traffic: 'low' },
      explanation: 'Real explanation text from the risk engine.',
    }

    render(<DualRiskPanel riskScore={riskScore} missingSteps={[]} />)

    expect(screen.getByText('75%')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
    expect(screen.getByText('Real explanation text from the risk engine.')).toBeInTheDocument()
    expect(screen.getByText('isolate_critical')).toBeInTheDocument()
    expect(screen.getByText('block_traffic')).toBeInTheDocument()

    const cyberMeter = screen.getByRole('progressbar', { name: 'Cyber risk score' })
    const clinicalMeter = screen.getByRole('progressbar', { name: 'Clinical risk score' })
    expect(cyberMeter).toHaveAttribute('aria-valuenow', '75')
    expect(clinicalMeter).toHaveAttribute('aria-valuenow', '40')
  })
})
