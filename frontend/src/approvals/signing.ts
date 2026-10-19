import type { ApprovalDecision } from '../api/types'

/**
 * Browser-side Ed25519 approval signing (WebCrypto). The signed message must be
 * byte-identical to the server's `approval_message` (backend/app/approvals/signing.py):
 * compact JSON with sorted keys, non-ASCII escaped the way Python's json.dumps does.
 * Shared golden vectors pin both sides (see signing.test.ts and
 * backend/app/approvals/tests/test_signing_vectors.py).
 */

export interface ApproverKey {
  identity: string
  privateKey: CryptoKey
  /** Base64 of the 32 raw public-key bytes, as APPROVER_PUBLIC_KEYS expects. */
  publicKeyB64: string
}

export interface ApprovalMessageInput {
  incidentId: string
  chosenAction: string
  policyRuleId: string
  decision: ApprovalDecision
  timestamp: Date
}

/** The server's canonical timestamp: UTC with microseconds (JS has milliseconds). */
export function formatTimestamp(date: Date): string {
  return date.toISOString().replace('Z', '000Z')
}

/** JSON.stringify, then escape what Python's ensure_ascii escapes (DEL and everything above ASCII). */
function pythonStyleJson(value: unknown): string {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (char) => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'),
  )
}

export function approvalMessage(input: ApprovalMessageInput): string {
  // Keys inserted in sorted order: matches json.dumps(sort_keys=True, separators=(",", ":")).
  return pythonStyleJson({
    chosen_action: input.chosenAction,
    decision: input.decision,
    incident_id: input.incidentId,
    policy_rule_id: input.policyRuleId,
    ts: formatTimestamp(input.timestamp),
    v: 1,
  })
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function signingSupported(): boolean {
  return typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle !== 'undefined'
}

/** Non-extractable private key: it can sign in this browser but can never be read out. */
export async function generateApproverKey(identity: string): Promise<ApproverKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair
  const raw = await crypto.subtle.exportKey('raw', pair.publicKey)
  return { identity, privateKey: pair.privateKey, publicKeyB64: bytesToBase64(new Uint8Array(raw)) }
}

export async function signApproval(key: ApproverKey, input: ApprovalMessageInput): Promise<string> {
  const message = new TextEncoder().encode(approvalMessage(input))
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, message)
  return bytesToBase64(new Uint8Array(signature))
}
