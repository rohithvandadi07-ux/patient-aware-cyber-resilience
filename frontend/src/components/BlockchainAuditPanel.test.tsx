import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { BlockchainAuditPanel } from './BlockchainAuditPanel'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderPanel() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <BlockchainAuditPanel incidentId="INC-1" />
    </QueryClientProvider>,
  )
}

describe('BlockchainAuditPanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('says nothing has been recorded yet when the audit trail is empty', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([]))

    renderPanel()

    expect(await screen.findByText(/No blockchain-provenance events recorded/)).toBeInTheDocument()
  })

  it('renders real outbox entries including an unconfirmed one as "not yet committed", never hidden', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(
      jsonResponse([
        {
          id: 1,
          record_type: 'incident',
          payload: {},
          created_at: '2026-10-12T00:00:00Z',
          status: 'pending',
          chain_tx_id: null,
          attempts: 0,
          last_error: null,
          updated_at: '2026-10-12T00:00:00Z',
        },
        {
          id: 2,
          record_type: 'decision',
          payload: {},
          created_at: '2026-10-12T00:05:00Z',
          status: 'confirmed',
          chain_tx_id: 'tx-abc',
          attempts: 1,
          last_error: null,
          updated_at: '2026-10-12T00:06:00Z',
        },
      ]),
    )

    renderPanel()

    expect(await screen.findByText('incident')).toBeInTheDocument()
    expect(screen.getByText('decision')).toBeInTheDocument()
    expect(screen.getByText('not yet committed')).toBeInTheDocument()
    expect(screen.getByText('tx-abc')).toBeInTheDocument()
    expect(screen.getByText('pending')).toBeInTheDocument()
    expect(screen.getByText('confirmed')).toBeInTheDocument()
  })

  it('processes pending entries via the real manual endpoint when clicked', async () => {
    const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>
    mockFetch.mockResolvedValueOnce(jsonResponse([])) // initial audit trail
    mockFetch.mockResolvedValueOnce(jsonResponse([])) // POST /blockchain/audit/process
    mockFetch.mockResolvedValueOnce(jsonResponse([])) // refetch after invalidation

    renderPanel()
    await screen.findByText(/No blockchain-provenance events recorded/)

    await userEvent.click(screen.getByRole('button', { name: 'Process pending entries' }))

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/blockchain/audit/process'),
      expect.objectContaining({ method: 'POST' }),
    )
  })
})
