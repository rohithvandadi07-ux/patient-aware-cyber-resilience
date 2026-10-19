import { useCallback, useEffect, useState } from 'react'
import { createIndexedDbKeyStore, type KeyStore } from './keystore'
import { generateApproverKey, signingSupported, type ApproverKey } from './signing'

export interface ApproverKeyState {
  /** The approver's signing key, or null when none has been created in this browser. */
  key: ApproverKey | null
  /** WebCrypto is available (needs a secure context: https or localhost). */
  supported: boolean
  create: (identity: string) => Promise<void>
  remove: () => Promise<void>
}

const defaultStore = createIndexedDbKeyStore()

export function useApproverKey(store: KeyStore = defaultStore): ApproverKeyState {
  const [key, setKey] = useState<ApproverKey | null>(null)

  useEffect(() => {
    let active = true
    store
      .load()
      .then((loaded) => {
        if (active) setKey(loaded)
      })
      .catch(() => {
        // An unreadable store behaves like "no key": approvals go out unsigned.
      })
    return () => {
      active = false
    }
  }, [store])

  const create = useCallback(
    async (identity: string) => {
      const created = await generateApproverKey(identity)
      await store.save(created)
      setKey(created)
    },
    [store],
  )

  const remove = useCallback(async () => {
    await store.clear()
    setKey(null)
  }, [store])

  return { key, supported: signingSupported(), create, remove }
}
