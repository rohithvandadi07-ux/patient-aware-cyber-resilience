import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ResponsePanel } from './ResponsePanel'

vi.mock('../approvals/useApproverKey', () => ({
  useApproverKey: () => ({
    key: { identity: 'dr-browser', privateKey: {}, publicKeyB64: 'PUB' },
    supported: true,
    create: vi.fn(),
    remove: vi.fn(),
  }),
}))
vi.mock('../approvals/signing', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../approvals/signing')>()),
  signApproval: vi.fn(async () => 'SIGNATURE'),
}))

const DECISION = {
  incident_id: 'INC-1',
  chosen_action: 'rotate_credentials',
  policy_rule_id: 'approval_high_impact',
  rationale: 'r',
  requires_human_approval: true,
  alternatives: [],
}

function mockFetch(responses: Record<string, unknown>) {
  const fn = vi.fn((url: string, _init?: RequestInit) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    const body = path in responses ? responses[path] : []
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('ResponsePanel with a signing key', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('signs the approval and sends it under the key identity', async () => {
    const fn = mockFetch({
      '/responses/proposed/INC-1': DECISION,
      '/responses/executed': { incident_id: 'INC-1', action_taken: 'rotate_credentials', executed_by: 'dr-browser', timestamp: '2026-10-19T10:00:00Z', chain_tx_id: null },
    })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <ResponsePanel incidentId="INC-1" traces={[]} riskScore={null} />
      </QueryClientProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: /approve/i }))

    await waitFor(() => {
      const call = fn.mock.calls.find((c) => c[0].endsWith('/responses/executed') && c[1]?.method === 'POST')
      expect(call).toBeDefined()
      const body = JSON.parse(String(call?.[1]?.body))
      expect(body.approval).toMatchObject({
        incident_id: 'INC-1',
        approver_identity: 'dr-browser',
        decision: 'approved',
        signature: 'SIGNATURE',
      })
    })
  })
})
