import { useState } from 'react'
import type { ApproverKeyState } from '../approvals/useApproverKey'

/**
 * The approver's identity and signing key. Without a key it is the plain
 * identity field (approvals go out unsigned); with one, approvals are signed in
 * this browser and the identity is the one the server has a public key for.
 */
export function ApproverKeyPanel({
  approver,
  identity,
  onIdentityChange,
}: {
  approver: ApproverKeyState
  identity: string
  onIdentityChange: (value: string) => void
}) {
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function run(action: () => Promise<void>) {
    setError(null)
    try {
      await action()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'unknown error')
    }
  }

  if (approver.key) {
    const entry = `${approver.key.identity}=${approver.key.publicKeyB64}`
    return (
      <div data-testid="approver-key" className="space-y-1 text-xs text-gray-600 dark:text-gray-300">
        <p>
          Signing as <strong>{approver.key.identity}</strong>. The key stays in this browser and cannot be exported.
        </p>
        <p>
          Server entry (add to <code>APPROVER_PUBLIC_KEYS</code>, comma-separated):
        </p>
        <p className="flex items-center gap-2">
          <code className="break-all">{entry}</code>
          <button
            type="button"
            className="shrink-0 underline"
            onClick={() =>
              run(async () => {
                await navigator.clipboard.writeText(entry)
                setCopied(true)
              })
            }
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </p>
        <button type="button" className="underline" onClick={() => run(approver.remove)}>
          Remove key
        </button>
        {error && <p role="alert" className="text-danger-600">{error}</p>}
      </div>
    )
  }

  return (
    <div className="space-y-1">
      <input
        type="text"
        placeholder="Approver identity"
        value={identity}
        onChange={(e) => onIdentityChange(e.target.value)}
        className="w-full rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-900"
      />
      {approver.supported ? (
        <button
          type="button"
          disabled={identity.trim() === ''}
          onClick={() => run(() => approver.create(identity.trim()))}
          className="text-xs underline disabled:cursor-not-allowed disabled:opacity-60"
        >
          Create signing key
        </button>
      ) : (
        <p className="text-xs text-gray-500">This browser cannot sign approvals here, so they are sent unsigned.</p>
      )}
      {error && <p role="alert" className="text-xs text-danger-600">{error}</p>}
    </div>
  )
}
