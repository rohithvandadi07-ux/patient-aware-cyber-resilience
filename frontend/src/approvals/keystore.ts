import type { ApproverKey } from './signing'

/**
 * Where the approver's signing key lives. The browser store keeps the
 * non-extractable CryptoKey in IndexedDB (structured clone), so the private key
 * never exists as readable bytes -- not in JS, not in storage.
 */
export interface KeyStore {
  load(): Promise<ApproverKey | null>
  save(key: ApproverKey): Promise<void>
  clear(): Promise<void>
}

const DB_NAME = 'pacr-approver'
const STORE = 'keys'
const RECORD = 'approver'

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => request.result.createObjectStore(STORE)
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

function run<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const request = action(db.transaction(STORE, mode).objectStore(STORE))
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
      }),
  )
}

export function createIndexedDbKeyStore(): KeyStore {
  return {
    async load() {
      if (typeof indexedDB === 'undefined') return null
      return ((await run<ApproverKey | undefined>('readonly', (s) => s.get(RECORD))) ?? null) as ApproverKey | null
    },
    async save(key) {
      if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is not available in this browser')
      await run('readwrite', (s) => s.put(key, RECORD))
    },
    async clear() {
      if (typeof indexedDB === 'undefined') return
      await run('readwrite', (s) => s.delete(RECORD))
    },
  }
}
