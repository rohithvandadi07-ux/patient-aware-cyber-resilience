import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Demo } from './Demo'

type Handler = (body: any) => unknown
interface Call {
  key: string
  body: any
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function mockApi(routes: Record<string, Handler>): Call[] {
  const calls: Call[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const path = url.replace(/^https?:\/\/[^/]+/, '')
      const key = `${init?.method ?? 'GET'} ${path}`
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ key, body })
      const handler = routes[key]
      return Promise.resolve(jsonResponse(handler ? handler(body) : []))
    }),
  )
  return calls
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Demo />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('Demo page', () => {
  it('explains that demo mode is off and offers no tools', async () => {
    mockApi({ 'GET /demo/status': () => ({ enabled: false }) })
    renderPage()
    expect(await screen.findByText(/demo mode is off/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /reset demo data/i })).toBeNull()
  })

  it('resets only after the confirmation step', async () => {
    const calls = mockApi({
      'GET /demo/status': () => ({ enabled: true }),
      'POST /demo/reset': () => ({
        incidents_removed: 3,
        proposed_removed: 1,
        executed_removed: 2,
        traces_removed: 0,
      }),
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /reset demo data/i }))
    expect(calls.some((c) => c.key === 'POST /demo/reset')).toBe(false)

    fireEvent.click(await screen.findByRole('button', { name: /yes, wipe everything/i }))
    expect(await screen.findByText(/removed 3 incidents/i)).toBeTruthy()
    expect(calls.some((c) => c.key === 'POST /demo/reset')).toBe(true)
  })

  it('launches the Wazuh scenario through /ingest/alerts and links the incident', async () => {
    const calls = mockApi({
      'GET /demo/status': () => ({ enabled: true }),
      'POST /ingest/alerts': () => ({ source: 'wazuh', outcomes: [], incident_ids: ['INC-W1'] }),
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /launch scenario: wazuh/i }))
    const link = await screen.findByRole('link', { name: 'INC-W1' })
    expect(link.getAttribute('href')).toBe('/incidents/INC-W1')
    const sent = calls.find((c) => c.key === 'POST /ingest/alerts')
    expect(sent?.body.source).toBe('wazuh')
    expect(sent?.body.alerts[0].agent.name).toBe('ventilator-01')
  })

  it('creates the pending-approval incident and its proposal', async () => {
    const calls = mockApi({
      'GET /demo/status': () => ({ enabled: true }),
      'POST /incidents': (body) => ({ incident_id: body.incident_id }),
      'POST /responses/proposed': () => ({}),
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /launch scenario: pending approval/i }))
    expect(await screen.findByRole('link', { name: /^DEMO-/ })).toBeTruthy()
    const proposed = calls.find((c) => c.key === 'POST /responses/proposed')
    expect(proposed?.body.proposed_response.recommended_action).toBe('rotate_credentials')
  })
})
