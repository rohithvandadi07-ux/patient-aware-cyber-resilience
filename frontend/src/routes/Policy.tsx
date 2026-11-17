import { ApiError } from '../api/client'
import { useAnchorPolicyMutation, usePolicy } from '../api/queries'
import type { PolicyAnchorView } from '../api/types'

const CARD = 'rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900'
const BUTTON =
  'rounded-md bg-cyber-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-900 disabled:opacity-50'
const BADGE = 'inline-block rounded px-2 py-0.5 text-xs font-medium'

function describeWhen(when: Record<string, unknown>): string {
  const parts = Object.entries(when).map(
    ([key, value]) =>
      `${key.replace(/_/g, ' ')}: ${Array.isArray(value) ? value.join(', ') : String(value)}`,
  )
  return parts.length > 0 ? parts.join(' · ') : 'always (catch-all)'
}

function AnchorStatus({ anchor }: { anchor: PolicyAnchorView }) {
  const mutation = useAnchorPolicyMutation()
  if (anchor.state === 'confirmed') {
    return (
      <p className="text-sm">
        <span className={`${BADGE} bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100`}>
          Anchored on ledger
        </span>{' '}
        transaction <code className="break-all">{anchor.chain_tx_id}</code>
      </p>
    )
  }
  if (anchor.state === 'pending') {
    return (
      <div className="space-y-2 text-sm">
        <p>
          <span className={`${BADGE} bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-100`}>
            Pending
          </span>{' '}
          Queued, waiting to be committed to the ledger.
        </p>
        <button
          type="button"
          className={BUTTON}
          disabled={mutation.isPending}
          onClick={() => mutation.mutate()}
        >
          Commit pending entries to ledger
        </button>
        <p className="text-xs text-gray-600 dark:text-gray-400">
          This commits every pending outbox entry, including this policy hash.
        </p>
        {mutation.isError && (
          <p role="alert" className="text-red-700 dark:text-red-400">
            {mutation.error instanceof ApiError ? mutation.error.message : 'The request failed.'}
          </p>
        )}
      </div>
    )
  }
  if (anchor.state === 'failed') {
    return (
      <div className="space-y-1 text-sm">
        <p>
          <span className={`${BADGE} bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100`}>
            Anchoring failed
          </span>
        </p>
        {anchor.last_error && <p className="text-gray-700 dark:text-gray-300">{anchor.last_error}</p>}
        <p className="text-xs text-gray-600 dark:text-gray-400">
          The backend queues the policy again the next time it starts.
        </p>
      </div>
    )
  }
  return (
    <p className="text-sm">
      <span className={`${BADGE} bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100`}>
        Not queued yet
      </span>{' '}
      The hash is queued when the backend starts.
    </p>
  )
}

export function Policy() {
  const policy = usePolicy()

  if (policy.isLoading) {
    return <p className="text-sm text-gray-600 dark:text-gray-400">Loading policy…</p>
  }
  if (policy.isError || !policy.data) {
    return (
      <p role="alert" className="text-sm text-red-700 dark:text-red-400">
        Could not load the routing policy.
      </p>
    )
  }
  const p = policy.data

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Routing policy</h1>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          The deterministic rules that decide whether a response runs autonomously or needs a human.
          No model is involved. Rules are checked top to bottom and the first match wins.
        </p>
      </header>

      <section className={`${CARD} space-y-3`} aria-label="Policy identity">
        <p className="text-sm">
          <span className="font-medium">{p.name}</span> · version {p.version} · source {p.source}
        </p>
        <p className="text-sm">
          SHA-256 <code className="break-all">{p.policy_hash}</code>
        </p>
        <AnchorStatus anchor={p.anchor} />
        <p className="text-xs text-gray-600 dark:text-gray-400">
          The hash covers the validated rules (comments and formatting do not change it). A changed
          policy gets a new hash, which is recorded the next time the backend starts.
        </p>
      </section>

      <section className={CARD} aria-label="Safety floor">
        <h2 className="text-sm font-semibold">Safety floor</h2>
        <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
          A policy that breaks any of these is refused when it is loaded.
        </p>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
          {p.safety_floor.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className={`${CARD} overflow-x-auto`} aria-label="Rules">
        <table className="w-full text-left text-sm">
          <caption className="pb-2 text-left text-sm font-semibold">Rules in evaluation order</caption>
          <thead className="text-xs uppercase text-gray-600 dark:text-gray-400">
            <tr>
              <th className="py-1 pr-3">#</th>
              <th className="py-1 pr-3">Rule</th>
              <th className="py-1 pr-3">When</th>
              <th className="py-1">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {p.rules.map((rule, index) => (
              <tr key={rule.id} className="border-t border-gray-100 align-top dark:border-gray-800">
                <td className="py-2 pr-3">{index + 1}</td>
                <td className="py-2 pr-3">
                  <code>{rule.id}</code>
                </td>
                <td className="py-2 pr-3">{describeWhen(rule.when)}</td>
                <td className="py-2">
                  {rule.requires_human_approval ? (
                    <span className={`${BADGE} bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-100`}>
                      Human approval
                    </span>
                  ) : (
                    <span className={`${BADGE} bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100`}>
                      Autonomous
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
