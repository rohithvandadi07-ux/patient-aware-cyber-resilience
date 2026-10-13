import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** Routes every request by its path (ignoring the `http://localhost:8000`
 * base) rather than by call order -- the Overview route alone fires three
 * parallel queries, so an order-dependent mock queue would be fragile. */
function mockFetchByPath(responses: Record<string, unknown>) {
  const mockFetch = vi.fn((url: string) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    if (path in responses) {
      return Promise.resolve(jsonResponse(responses[path]))
    }
    return Promise.resolve(jsonResponse([]))
  })
  vi.stubGlobal('fetch', mockFetch)
  return mockFetch
}

describe('App', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('wires the router and query client together and renders the Executive Overview at /', async () => {
    mockFetchByPath({ '/incidents': [], '/devices': [], '/agents': [] })

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Executive Overview' })).toBeInTheDocument()
  })

  // One continuous journey, not separate `it`s that each remount <App/> --
  // `App.tsx`'s `QueryClient` is a module-level singleton (by design, so
  // navigating between real routes shares one real cache), so separate
  // tests remounting it would read a previous test's stale cache instead
  // of exercising a fresh load.
  it('navigates through every primary nav destination on one query client', async () => {
    mockFetchByPath({
      '/incidents': [],
      '/devices': [],
      '/agents': [],
      '/telemetry': [],
      '/events': [],
      '/blockchain/audit': [],
      '/responses/executed': [],
      '/recovery': [],
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'Executive Overview' })

    await userEvent.click(screen.getByRole('link', { name: 'Incidents' }))
    expect(await screen.findByRole('heading', { name: 'Incidents' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run Scenario' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('link', { name: 'Fleet' }))
    expect(await screen.findByRole('heading', { name: 'IoMT Fleet' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('link', { name: 'Threat Monitor' }))
    expect(await screen.findByRole('heading', { name: 'Threat Monitor' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('link', { name: 'Analytics' }))
    expect(await screen.findByRole('heading', { name: 'Historical Incidents & Analytics' })).toBeInTheDocument()
  })
})
