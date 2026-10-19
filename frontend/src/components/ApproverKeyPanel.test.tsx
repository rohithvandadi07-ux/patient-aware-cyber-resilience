import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ApproverKeyState } from '../approvals/useApproverKey'
import { ApproverKeyPanel } from './ApproverKeyPanel'

function state(overrides: Partial<ApproverKeyState> = {}): ApproverKeyState {
  return { key: null, supported: true, create: vi.fn(async () => {}), remove: vi.fn(async () => {}), ...overrides }
}

const KEY = { identity: 'dr-browser', privateKey: {} as CryptoKey, publicKeyB64: 'PUBKEY=' }

describe('ApproverKeyPanel', () => {
  afterEach(cleanup)

  it('is a plain identity field until a key exists', () => {
    render(<ApproverKeyPanel approver={state()} identity="" onIdentityChange={() => {}} />)
    expect(screen.getByPlaceholderText('Approver identity')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create signing key' })).toBeDisabled()
  })

  it('creates a key for the typed identity', async () => {
    const approver = state()
    render(<ApproverKeyPanel approver={approver} identity="  dr-browser " onIdentityChange={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'Create signing key' }))
    await waitFor(() => expect(approver.create).toHaveBeenCalledWith('dr-browser'))
  })

  it('shows the server entry and the signing identity once a key exists', () => {
    render(<ApproverKeyPanel approver={state({ key: KEY })} identity="" onIdentityChange={() => {}} />)
    const panel = screen.getByTestId('approver-key')
    expect(panel).toHaveTextContent('Signing as dr-browser')
    expect(panel).toHaveTextContent('dr-browser=PUBKEY=')
    expect(screen.queryByPlaceholderText('Approver identity')).not.toBeInTheDocument()
  })

  it('removes the key', async () => {
    const approver = state({ key: KEY })
    render(<ApproverKeyPanel approver={approver} identity="" onIdentityChange={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove key' }))
    await waitFor(() => expect(approver.remove).toHaveBeenCalled())
  })

  it('says plainly when signing is unavailable', () => {
    render(<ApproverKeyPanel approver={state({ supported: false })} identity="x" onIdentityChange={() => {}} />)
    expect(screen.getByText(/sent unsigned/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create signing key' })).not.toBeInTheDocument()
  })

  it('surfaces a failure to create a key', async () => {
    const approver = state({ create: vi.fn(async () => { throw new Error('Ed25519 is not supported') }) })
    render(<ApproverKeyPanel approver={approver} identity="dr-x" onIdentityChange={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'Create signing key' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Ed25519 is not supported')
  })
})
