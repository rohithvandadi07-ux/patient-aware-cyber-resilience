import { useState } from 'react'
import { signApproval } from '../approvals/signing'
import { useApproverKey } from '../approvals/useApproverKey'
import { ApproverKeyPanel } from './ApproverKeyPanel'
import { deriveProposeResponseRequest } from '../api/proposeResponseFromTraces'
import { useExecuteResponseMutation, useExecutedResponses, useProposeResponseMutation, useProposedResponse } from '../api/queries'
import type { AgentTrace, ApprovalDecision, RiskScore } from '../api/types'

/** The connected patient's acuity as recorded by the Healthcare Context
 * Agent (grounded server-side from the patient registry). Read from the
 * traces this view already has -- no extra request. */
function connectedPatient(traces: AgentTrace[]): { acuity: string; news2: number | null } | null {
  for (const trace of [...traces].reverse()) {
    const payload = trace.output_payload
    if (!trace.succeeded || !payload) continue
    const acuity = payload['patient_acuity']
    if (typeof acuity === 'string') {
      const news2 = payload['news2_score']
      return { acuity, news2: typeof news2 === 'number' ? news2 : null }
    }
  }
  return null
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

/**
 * The Policy Engine's decision (`PolicyDecision`, real and persisted --
 * `GET /responses/proposed/{incident_id}`, Section 7 step 9) and the
 * Response Orchestrator's executions (`ExecutedResponse`, real and
 * persisted -- Section 7 step 11). Proposing feeds the orchestrator a real
 * `RiskScore` + `ProposedResponse` + `ClinicalContext` built from this
 * incident's own agent traces and already-computed risk score (see
 * `proposeResponseFromTraces.ts`) -- never fabricated inputs. Executing
 * follows the backend's own rule: a decision that `requires_human_approval`
 * is refused (409 `ApprovalRequiredError`) without a real `ApprovalRecord`,
 * so this panel asks for one rather than silently attaching a fake
 * approval.
 */
export function ResponsePanel({
  incidentId,
  traces,
  riskScore,
}: {
  incidentId: string
  traces: AgentTrace[]
  riskScore: RiskScore | null
}) {
  const proposedQuery = useProposedResponse(incidentId)
  const executedQuery = useExecutedResponses(incidentId)
  const proposeResponse = useProposeResponseMutation()
  const executeResponse = useExecuteResponseMutation()

  const [approverIdentity, setApproverIdentity] = useState('')
  const [notes, setNotes] = useState('')
  const approver = useApproverKey()
  const [signError, setSignError] = useState<string | null>(null)

  const derivation = deriveProposeResponseRequest(traces, riskScore)
  const patient = connectedPatient(traces)

  function handlePropose() {
    if (!derivation.request) return
    proposeResponse.mutate(derivation.request)
  }

  async function handleExecute(decision: ApprovalDecision | null) {
    setSignError(null)
    if (decision === null) {
      executeResponse.mutate({ incident_id: incidentId, approval: null })
      return
    }
    const timestamp = new Date()
    const approval = {
      incident_id: incidentId,
      approver_identity: approver.key?.identity ?? approverIdentity,
      decision,
      timestamp: timestamp.toISOString(),
      notes: notes.trim() === '' ? null : notes.trim(),
    }
    const pending = proposedQuery.data
    if (approver.key && pending) {
      try {
        const signature = await signApproval(approver.key, {
          incidentId,
          chosenAction: pending.chosen_action,
          policyRuleId: pending.policy_rule_id,
          decision,
          timestamp,
        })
        executeResponse.mutate({ incident_id: incidentId, approval: { ...approval, signature } })
      } catch (error) {
        setSignError(error instanceof Error ? error.message : 'unknown error')
      }
      return
    }
    executeResponse.mutate({ incident_id: incidentId, approval })
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Proposed response</h3>

        {proposedQuery.isLoading && <p className="text-sm text-gray-500">Checking for a pending decision…</p>}

        {proposedQuery.isSuccess && proposedQuery.data && (
          <div className="space-y-2 text-sm">
            {patient && (
              <p
                data-testid="connected-patient"
                className={`rounded px-2 py-1 text-xs font-medium ${
                  patient.acuity === 'high'
                    ? 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300'
                    : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300'
                }`}
              >
                {`Connected patient: ${patient.acuity} acuity${patient.news2 !== null ? ` (NEWS2 ${patient.news2})` : ''}`}
              </p>
            )}
            <p>
              <span className="font-medium text-gray-500 dark:text-gray-400">Chosen action: </span>
              {proposedQuery.data.chosen_action}
            </p>
            <p>
              <span className="font-medium text-gray-500 dark:text-gray-400">Policy rule: </span>
              {proposedQuery.data.policy_rule_id}
            </p>
            <p className="text-gray-600 dark:text-gray-300">{proposedQuery.data.rationale}</p>

            {(proposedQuery.data.alternatives?.length ?? 0) > 0 && (
              <div>
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-400">
                  Alternatives considered
                </h4>
                <table className="w-full text-left text-xs">
                  <thead className="text-gray-400">
                    <tr>
                      <th className="py-1 pr-2 font-medium">Action</th>
                      <th className="py-1 pr-2 font-medium">Clinical impact</th>
                      <th className="py-1 pr-2 font-medium">Routing</th>
                      <th className="py-1 font-medium">Security benefit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {proposedQuery.data.alternatives!.map((alt) => (
                      <tr key={alt.action} className="border-t border-gray-100 dark:border-gray-800/60">
                        <td className="py-1 pr-2">{alt.action}</td>
                        <td className="py-1 pr-2">{alt.response_impact}</td>
                        <td className="py-1 pr-2" title={alt.policy_rule_id}>
                          {alt.requires_human_approval ? 'needs approval' : 'autonomous'}
                        </td>
                        <td className="py-1">{alt.security_benefit === null ? '—' : alt.security_benefit.toFixed(2)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {proposedQuery.data.requires_human_approval ? (
              <div className="space-y-2 rounded border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950">
                <p className="text-xs font-medium text-amber-700 dark:text-amber-300">
                  Requires human approval before execution.
                </p>
                <ApproverKeyPanel approver={approver} identity={approverIdentity} onIdentityChange={setApproverIdentity} />
                <input
                  type="text"
                  placeholder="Notes (optional)"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-900"
                />
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => handleExecute('approved')}
                    disabled={(approver.key === null && approverIdentity.trim() === '') || executeResponse.isPending}
                    className="rounded-md bg-clinical-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-clinical-700 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Approve &amp; execute
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExecute('rejected')}
                    disabled={(approver.key === null && approverIdentity.trim() === '') || executeResponse.isPending}
                    className="rounded-md bg-danger-600 px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => handleExecute(null)}
                disabled={executeResponse.isPending}
                className="rounded-md bg-cyber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {executeResponse.isPending ? 'Executing…' : 'Execute (no approval required)'}
              </button>
            )}
          </div>
        )}

        {proposedQuery.isSuccess && !proposedQuery.data && (
          <div className="space-y-2">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              No response proposed yet.{' '}
              {derivation.missingSteps.length > 0 &&
                `Waiting on: ${derivation.missingSteps.join(', ')}.`}
            </p>
            <button
              type="button"
              onClick={handlePropose}
              disabled={!derivation.request || proposeResponse.isPending}
              className="rounded-md bg-cyber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {proposeResponse.isPending ? 'Proposing…' : 'Propose response'}
            </button>
          </div>
        )}

        {proposeResponse.isError && (
          <p className="mt-2 text-sm text-danger-600" role="alert">
            Propose failed: {proposeResponse.error instanceof Error ? proposeResponse.error.message : 'unknown error'}
          </p>
        )}
        {signError && (
          <p className="mt-2 text-sm text-danger-600" role="alert">
            Signing failed: {signError}
          </p>
        )}
        {executeResponse.isError && (
          <p className="mt-2 text-sm text-danger-600" role="alert">
            Execute failed: {executeResponse.error instanceof Error ? executeResponse.error.message : 'unknown error'}
          </p>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Executed responses</h3>
        {executedQuery.isSuccess && executedQuery.data.length === 0 && (
          <p className="text-sm text-gray-500 dark:text-gray-400">No response has been executed yet.</p>
        )}
        {executedQuery.isSuccess && executedQuery.data.length > 0 && (
          <ul className="space-y-1 text-sm">
            {executedQuery.data.map((executed, i) => (
              <li key={i} className="flex items-center justify-between border-b border-gray-100 py-1 last:border-0 dark:border-gray-800/60">
                <span>
                  {executed.action_taken} by {executed.executed_by} at {formatTimestamp(executed.timestamp)}
                </span>
                <span className="text-xs text-gray-400">{executed.chain_tx_id ?? 'not yet committed'}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
