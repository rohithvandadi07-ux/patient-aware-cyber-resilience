import { deriveRecoveryResult } from '../api/recoveryResultFromTraces'
import { useProcessRecoveryResultMutation, useRecoveryResults } from '../api/queries'
import type { AgentTrace } from '../api/types'

/**
 * `POST /recovery` (Section 7 step 12) takes a real `RecoveryResult` --
 * this panel's only source for one is a successful `recovery_verification`
 * agent trace (see `recoveryResultFromTraces.ts`), never a guess at whether
 * containment held. Submitting it is what actually resolves or reopens the
 * incident server-side (`RecoveryOrchestrator`), so the already-submitted
 * list below is the real audit of that decision, not a local echo of it.
 */
export function RecoveryPanel({ incidentId, traces }: { incidentId: string; traces: AgentTrace[] }) {
  const recoveryResultsQuery = useRecoveryResults(incidentId)
  const processRecoveryResult = useProcessRecoveryResultMutation()

  const derivation = deriveRecoveryResult(traces)

  function handleSubmit() {
    if (!derivation.result) return
    processRecoveryResult.mutate(derivation.result)
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Verify recovery</h3>
        {derivation.result ? (
          <div className="space-y-2 text-sm">
            <p>
              <span className="font-medium text-gray-500 dark:text-gray-400">Containment verified: </span>
              {derivation.result.containment_verified ? 'yes' : 'no'}
            </p>
            <p>
              <span className="font-medium text-gray-500 dark:text-gray-400">Recovery succeeded: </span>
              {derivation.result.recovery_succeeded ? 'yes' : 'no'}
            </p>
            {derivation.result.residual_threats.length > 0 && (
              <p>
                <span className="font-medium text-gray-500 dark:text-gray-400">Residual threats: </span>
                {derivation.result.residual_threats.join(', ')}
              </p>
            )}
            <button
              type="button"
              onClick={handleSubmit}
              disabled={processRecoveryResult.isPending}
              className="rounded-md bg-cyber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {processRecoveryResult.isPending ? 'Submitting…' : 'Submit recovery result'}
            </button>
          </div>
        ) : (
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Not yet verified. Waiting on: {derivation.missingSteps.join(', ')}.
          </p>
        )}
        {processRecoveryResult.isError && (
          <p className="mt-2 text-sm text-danger-600" role="alert">
            Submit failed:{' '}
            {processRecoveryResult.error instanceof Error ? processRecoveryResult.error.message : 'unknown error'}
          </p>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Submitted recovery results</h3>
        {recoveryResultsQuery.isSuccess && recoveryResultsQuery.data.length === 0 && (
          <p className="text-sm text-gray-500 dark:text-gray-400">No recovery result has been submitted yet.</p>
        )}
        {recoveryResultsQuery.isSuccess && recoveryResultsQuery.data.length > 0 && (
          <ul className="space-y-1 text-sm">
            {recoveryResultsQuery.data.map((result, i) => (
              <li key={i} className="border-b border-gray-100 py-1 last:border-0 dark:border-gray-800/60">
                response {result.response_id}: {result.recovery_succeeded ? 'succeeded' : 'failed'}
                {result.reinvestigation_required && ' (reinvestigation required)'}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
