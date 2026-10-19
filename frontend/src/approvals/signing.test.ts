// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { approvalMessage, formatTimestamp, generateApproverKey, signApproval, type ApproverKey } from './signing'

// Golden vectors produced by the server's own code (backend/app/approvals/signing.py).
// The same vectors are asserted on the Python side, so a change on either side fails a test.
const TIMESTAMP = new Date('2026-10-19T10:00:00.123Z')
const BASE = {
  chosenAction: 'rotate_credentials',
  policyRuleId: 'approval_high_impact',
  decision: 'approved' as const,
  timestamp: TIMESTAMP,
}
const PLAIN_ID = 'INC-ventilator-01-ab12cd34'
const PLAIN_MESSAGE =
  '{"chosen_action":"rotate_credentials","decision":"approved","incident_id":"INC-ventilator-01-ab12cd34","policy_rule_id":"approval_high_impact","ts":"2026-10-19T10:00:00.123000Z","v":1}'
const PLAIN_SIGNATURE = 'wpTWVY1PVVem7mO40vu+Vnmy4TjwAO5DJFtrU5Ov8RjUnwN+DfvCfv0Zr3kCL8zIZqiLyX4DyOL7V/VIEwdrCA=='
const UNICODE_ID = 'INC-\u00e9-\u{1F600}-\x7f'
const UNICODE_MESSAGE =
  '{"chosen_action":"rotate_credentials","decision":"approved","incident_id":"INC-\\u00e9-\\ud83d\\ude00-\\u007f","policy_rule_id":"approval_high_impact","ts":"2026-10-19T10:00:00.123000Z","v":1}'
const UNICODE_SIGNATURE = 'BYf1jiXJT2NX7Wx6E1Tl39JQuRlekihf9OGTmfTGfHDFG8vvIJDJfGosU+LP/6drx8wbNmNvTXsAgxM72NytDw=='
const PUBLIC_KEY = 'A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg='
const SEED = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='

function fromBase64(value: string) {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// PKCS#8 wrapper for a raw 32-byte Ed25519 seed (WebCrypto imports private keys in this form).
const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])

async function goldenKey(): Promise<ApproverKey> {
  const seed = fromBase64(SEED)
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seed.length)
  pkcs8.set(PKCS8_PREFIX)
  pkcs8.set(seed, PKCS8_PREFIX.length)
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
  return { identity: 'golden', privateKey, publicKeyB64: PUBLIC_KEY }
}

describe('approval message', () => {
  it('matches the server byte for byte', () => {
    expect(approvalMessage({ ...BASE, incidentId: PLAIN_ID })).toBe(PLAIN_MESSAGE)
  })

  it('escapes non-ASCII and DEL exactly as Python json.dumps does', () => {
    expect(approvalMessage({ ...BASE, incidentId: UNICODE_ID })).toBe(UNICODE_MESSAGE)
  })

  it('uses microsecond UTC timestamps', () => {
    expect(formatTimestamp(TIMESTAMP)).toBe('2026-10-19T10:00:00.123000Z')
  })
})

describe('approval signature', () => {
  it('reproduces the server-side golden signatures (Ed25519 is deterministic)', async () => {
    const key = await goldenKey()
    expect(await signApproval(key, { ...BASE, incidentId: PLAIN_ID })).toBe(PLAIN_SIGNATURE)
    expect(await signApproval(key, { ...BASE, incidentId: UNICODE_ID })).toBe(UNICODE_SIGNATURE)
  })

  it('a freshly generated key signs messages its public key verifies, and the private key cannot be exported', async () => {
    const key = await generateApproverKey('dr-browser')
    const signature = await signApproval(key, { ...BASE, incidentId: PLAIN_ID })
    const publicKey = await crypto.subtle.importKey('raw', fromBase64(key.publicKeyB64), { name: 'Ed25519' }, false, ['verify'])
    const message = new TextEncoder().encode(PLAIN_MESSAGE)
    expect(await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, fromBase64(signature), message)).toBe(true)
    expect(key.publicKeyB64).toHaveLength(44)
    await expect(crypto.subtle.exportKey('pkcs8', key.privateKey)).rejects.toThrow()
  })
})
