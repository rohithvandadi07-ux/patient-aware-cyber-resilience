import { useAuditTrail, useProcessOutboxMutation } from '../api/queries'

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  confirmed: 'bg-clinical-100 text-clinical-700 dark:bg-clinical-900 dark:text-clinical-300',
  failed: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

/**
 * The real outbox entries for this incident (`GET /blockchain/audit/{id}`)
 * -- every incident, decision, approval, response, and recovery event this
 * incident has actually produced, each one honestly `pending`, `confirmed`,
 * or `failed` rather than assumed committed. There is no background
 * draining loop (a documented gap -- `app/blockchain/README.md`), so
 * "Process pending entries" is a real manual trigger for
 * `POST /blockchain/audit/process`, not a cosmetic refresh button.
 */
export function BlockchainAuditPanel({ incidentId }: { incidentId: string }) {
  const auditTrailQuery = useAuditTrail(incidentId)
  const processOutbox = useProcessOutboxMutation()

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-400">
          No background loop drains this outbox -- entries stay "pending" until processed manually.
        </p>
        <button
          type="button"
          onClick={() => processOutbox.mutate()}
          disabled={processOutbox.isPending}
          className="rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-gray-700 dark:hover:bg-gray-800"
        >
          {processOutbox.isPending ? 'Processing…' : 'Process pending entries'}
        </button>
      </div>

      {processOutbox.isError && (
        <p className="text-sm text-danger-600" role="alert">
          Processing failed: {processOutbox.error instanceof Error ? processOutbox.error.message : 'unknown error'}
        </p>
      )}

      {auditTrailQuery.isLoading && <p className="text-sm text-gray-500">Loading audit trail…</p>}
      {auditTrailQuery.isSuccess && auditTrailQuery.data.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400">
          No blockchain-provenance events recorded for this incident yet.
        </p>
      )}
      {auditTrailQuery.isSuccess && auditTrailQuery.data.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-gray-200 text-gray-500 dark:border-gray-800 dark:text-gray-400">
              <th className="py-1 pr-4 font-medium">Record type</th>
              <th className="py-1 pr-4 font-medium">Status</th>
              <th className="py-1 pr-4 font-medium">Chain tx</th>
              <th className="py-1 pr-4 font-medium">Created</th>
            </tr>
          </thead>
          <tbody>
            {auditTrailQuery.data.map((entry) => (
              <tr key={entry.id} className="border-b border-gray-100 last:border-0 dark:border-gray-800/60">
                <td className="py-1 pr-4">{entry.record_type}</td>
                <td className="py-1 pr-4">
                  <span
                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[entry.status]}`}
                  >
                    {entry.status}
                  </span>
                  {entry.status === 'failed' && entry.last_error && (
                    <span className="ml-2 text-xs text-danger-600">{entry.last_error}</span>
                  )}
                </td>
                <td className="py-1 pr-4 text-gray-500 dark:text-gray-400">
                  {entry.chain_tx_id ?? <span className="italic">not yet committed</span>}
                </td>
                <td className="py-1 pr-4 text-gray-500 dark:text-gray-400">{formatTimestamp(entry.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
