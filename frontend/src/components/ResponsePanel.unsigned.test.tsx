import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ResponsePanel } from './ResponsePanel'

// No key in this browser (jsdom has no IndexedDB): the original unsigned flow must still work.
const DECISION = {
  incident_id: 'INC-2',
  chosen_action: 'rotate_credentials',
  policy_rule_id: 'approval_high_impact',
  rationale: 'r',
  requires_human_approval: true,
  alternatives: [],
}

describe('ResponsePanel without a signing key', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('still sends the typed identity, unsigned', async () => {
    const fn = vi.fn((url: string, _init?: RequestInit) => {
      const path = url.replace(/^https?:\/\/[^/]+/, '')
      const body = path === '/responses/proposed/INC-2' ? DECISION : path === '/responses/executed' ? { incident_id: 'INC-2', action_taken: 'rotate_credentials', executed_by: 'dr-typed', timestamp: '2026-10-19T10:00:00Z', chain_tx_id: null } : []
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    })
    vi.stubGlobal('fetch', fn)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <ResponsePanel incidentId="INC-2" traces={[]} riskScore={null} />
      </QueryClientProvider>,
    )

    fireEvent.change(await screen.findByPlaceholderText('Approver identity'), { target: { value: 'dr-typed' } })
    fireEvent.click(screen.getByRole('button', { name: /approve/i }))

    await waitFor(() => {
      const call = fn.mock.calls.find((c) => c[0].endsWith('/responses/executed') && c[1]?.method === 'POST')
      expect(call).toBeDefined()
      const approval = JSON.parse(String(call?.[1]?.body)).approval
      expect(approval.approver_identity).toBe('dr-typed')
      expect(approval.signature).toBeUndefined()
    })
  })
})
