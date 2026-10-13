import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { AGENT_LABELS } from '../agentLabels'
import { useAgentTraces, useCalculateRiskMutation, useIncident } from '../api/queries'
import { deriveRiskAssessmentRequest } from '../api/riskAssessmentFromTraces'
import type { RiskScore } from '../api/types'
import { AgentActivityPanel } from '../components/AgentActivityPanel'
import { BlockchainAuditPanel } from '../components/BlockchainAuditPanel'
import { DualRiskPanel } from '../components/DualRiskPanel'
import { EvidencePanel } from '../components/EvidencePanel'
import { Panel } from '../components/Panel'
import { RecoveryPanel } from '../components/RecoveryPanel'
import { ResponsePanel } from '../components/ResponsePanel'
import { StatusBadge } from '../components/StatusBadge'

/**
 * The Phase 10 gate view: one incident's full lifecycle -- header, the dual
 * cyber-risk / clinical-risk panel (Section 16), Agent Activity, Evidence,
 * Response, Recovery, and Blockchain Audit. Every panel reads real data
 * (agent traces, persisted policy decisions and executed responses,
 * submitted recovery results, the real outbox) and shows an honest "not
 * yet" state when that data doesn't exist yet -- never placeholder content.
 *
 * The risk score itself is never fetched by id -- the backend's Risk Engine
 * is deliberately stateless (`app/api/risk_assessments.py`: no
 * `risk_assessments` table in the architecture's storage section) -- so it
 * lives in local state here, computed by calling the real endpoint with
 * real upstream agent-trace data (see `riskAssessmentFromTraces.ts`), the
 * same way a human operator triggering that step would.
 */
export function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>()
  const incidentQuery = useIncident(incidentId ?? '')
  const agentTracesQuery = useAgentTraces(incidentId ?? '')
  const calculateRisk = useCalculateRiskMutation()
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null)

  if (!incidentId) {
    return <p className="text-sm text-danger-600">No incident id in the URL.</p>
  }

  const derivation = agentTracesQuery.data ? deriveRiskAssessmentRequest(agentTracesQuery.data) : null
  const missingSteps = (derivation?.missingSteps ?? []).map((agent) => AGENT_LABELS[agent])

  function handleAssessRisk() {
    if (!derivation?.request) return
    calculateRisk.mutate(derivation.request, {
      onSuccess: (result) => setRiskScore(result),
    })
  }

  return (
    <div className="space-y-4">
      <Link to="/incidents" className="text-sm text-cyber-700 hover:underline dark:text-cyber-300">
        ← All incidents
      </Link>

      {incidentQuery.isLoading && <p className="text-sm text-gray-500">Loading incident…</p>}
      {incidentQuery.isError && (
        <p className="text-sm text-danger-600" role="alert">
          Failed to load incident {incidentId}:{' '}
          {incidentQuery.error instanceof Error ? incidentQuery.error.message : 'unknown error'}
        </p>
      )}

      {incidentQuery.isSuccess && (
        <>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-semibold">{incidentQuery.data.incident_id}</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Device <span className="font-medium">{incidentQuery.data.device_id}</span>
              </p>
            </div>
            <StatusBadge status={incidentQuery.data.status} />
          </div>

          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
              Dual Risk Assessment
            </h2>
            <button
              type="button"
              onClick={handleAssessRisk}
              disabled={!derivation?.request || calculateRisk.isPending}
              className="rounded-md bg-cyber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {calculateRisk.isPending ? 'Assessing…' : 'Assess risk'}
            </button>
          </div>

          {calculateRisk.isError && (
            <p className="text-sm text-danger-600" role="alert">
              Risk assessment failed:{' '}
              {calculateRisk.error instanceof Error ? calculateRisk.error.message : 'unknown error'}
            </p>
          )}

          <DualRiskPanel riskScore={riskScore} missingSteps={missingSteps} />

          <Panel title="Agent Activity">
            <AgentActivityPanel traces={agentTracesQuery.data ?? []} />
          </Panel>

          <Panel title="Evidence">
            <EvidencePanel traces={agentTracesQuery.data ?? []} />
          </Panel>

          <Panel title="Response">
            <ResponsePanel incidentId={incidentId} traces={agentTracesQuery.data ?? []} riskScore={riskScore} />
          </Panel>

          <Panel title="Recovery">
            <RecoveryPanel incidentId={incidentId} traces={agentTracesQuery.data ?? []} />
          </Panel>

          <Panel title="Blockchain Audit">
            <BlockchainAuditPanel incidentId={incidentId} />
          </Panel>
        </>
      )}
    </div>
  )
}
