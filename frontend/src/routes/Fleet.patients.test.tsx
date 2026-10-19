import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DeviceState, PatientState } from '../api/types'
import { Fleet } from './Fleet'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetch(responses: Record<string, unknown>) {
  const fn = vi.fn((url: string, _init?: RequestInit) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    return Promise.resolve(jsonResponse(path in responses ? responses[path] : []))
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

function renderFleet() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Fleet />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const ventilator: DeviceState = {
  device_id: 'ventilator-01',
  device_type: 'ventilator',
  criticality: 'high',
  patient_dependency: true,
  synthetic_patient_id: 'synthetic-patient-001',
  operational_state: 'active',
  network_state: 'connected',
}

const pump: DeviceState = {
  device_id: 'infusion-pump-02',
  device_type: 'infusion_pump',
  criticality: 'medium',
  patient_dependency: false,
  synthetic_patient_id: null,
  operational_state: 'active',
  network_state: 'connected',
}

const patient: PatientState = {
  patient_id: 'synthetic-patient-001',
  device_ids: ['ventilator-01'],
  profile: 'ventilated_critical',
  simulated_minute: 0,
  vitals: {
    respiration_rate: 23.5,
    spo2: 93,
    on_supplemental_oxygen: true,
    systolic_bp: 106.7,
    pulse: 110.5,
    consciousness: 'alert',
    temperature_c: 37.8,
  },
  news2_score: 8,
  score_breakdown: {},
  single_parameter_red_flag: false,
  acuity_band: 'high',
}

describe('Fleet patient condition', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the live NEWS2 score and acuity band for a device with a patient', async () => {
    mockFetch({ '/devices': [ventilator], '/patients': [patient] })
    renderFleet()

    expect(await screen.findByText('ventilator-01')).toBeInTheDocument()
    expect(await screen.findByText('NEWS2 8')).toBeInTheDocument()
    expect(screen.getByText('high acuity')).toBeInTheDocument()
  })

  it('says so plainly when a device has no linked patient', async () => {
    mockFetch({ '/devices': [pump], '/patients': [patient] })
    renderFleet()

    expect(await screen.findByText('infusion-pump-02')).toBeInTheDocument()
    expect(screen.getByText('no patient linked')).toBeInTheDocument()
  })

  it('advances the patient clock by 30 minutes when the button is clicked', async () => {
    const fn = mockFetch({ '/devices': [ventilator], '/patients': [patient] })
    renderFleet()

    expect(await screen.findByText(/minute 0/)).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: /advance patient clock/i }))

    await waitFor(() => {
      const call = fn.mock.calls.find((c) => c[0].endsWith('/patients/clock/advance'))
      expect(call).toBeDefined()
      expect(call?.[1]?.method).toBe('POST')
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ minutes: 30 })
    })
  })
})
