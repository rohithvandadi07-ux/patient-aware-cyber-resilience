import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import * as client from '../api/client'
import { ApiError } from '../api/client'
import { queryKeys, useDemoResetMutation, useDemoStatus } from '../api/queries'
import type { IncidentCreateRequest, ProposeResponseRequest } from '../api/types'

interface Scenario {
  id: string
  title: string
  description: string
  /** Resolves to the ids of the incidents the scenario opened. */
  run: () => Promise<string[]>
}

const CARD = 'rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900'
const BUTTON =
  'rounded-md bg-cyber-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyber-900 disabled:opacity-50'

function describeError(error: unknown): string {
  return error instanceof ApiError ? error.message : 'The request failed.'
}

async function launchSuricata(): Promise<string[]> {
  const now = Date.now()
  const result = await client.ingestAlerts({
    source: 'suricata_eve',
    device_id: 'infusion-pump-01',
    alerts: [
      {
        timestamp: new Date(now).toISOString(),
        event_type: 'alert',
        flow_id: now % 100000,
        src_ip: '10.0.0.9',
        dest_ip: '10.0.1.10',
        proto: 'TCP',
        alert: {
          signature: 'ET DOS Possible SYN flood',
          category: 'Attempted Denial of Service',
          severity: 1,
          signature_id: 2001,
        },
      },
    ],
  })
  return result.incident_ids
}

async function launchWazuh(): Promise<string[]> {
  const now = Date.now()
  const result = await client.ingestAlerts({
    source: 'wazuh',
    alerts: [
      {
        id: `${Math.floor(now / 1000)}.1`,
        timestamp: new Date(now).toISOString(),
        rule: {
          id: '100200',
          level: 10,
          description: 'MQTT unauthorized publish to ventilator command topic',
          groups: ['mqtt', 'iot'],
        },
        agent: { id: '004', name: 'ventilator-01', ip: '10.0.1.20' },
        data: { srcip: '10.0.0.66' },
      },
    ],
  })
  return result.incident_ids
}

async function launchPendingApproval(): Promise<string[]> {
  const id = `DEMO-${Date.now() % 100000}`
  const action = 'rotate_credentials'
  await client.createIncident({
    incident_id: id,
    device_id: 'ventilator-01',
    attack_type: 'mqtt_based',
    evidence_ref: `ev-${id}`,
    timestamp: new Date().toISOString(),
  } as IncidentCreateRequest)
  // Same payload as scripts/make_pending_approval.py (no LLM involved).
  const proposal = {
    risk_score: {
      incident_id: id,
      cyber_risk: 0.8,
      clinical_risk: 0.5,
      response_impact: { [action]: 'high' },
      explanation: 'scripted for the demo',
    },
    proposed_response: {
      incident_id: id,
      candidate_actions: [{ action_category: action, description: 'Rotate device credentials' }],
      security_benefit: { [action]: 0.7 },
      clinical_impact: { [action]: 'high' },
      recommended_action: action,
      rationale: 'scripted for the demo',
    },
    context: {
      incident_id: id,
      device_criticality: 'high',
      patient_dependency: true,
      clinical_impact_level: 'high',
      safety_constraints: [],
    },
  } as unknown as ProposeResponseRequest
  await client.proposeResponse(proposal)
  return [id]
}

const SCENARIOS: Scenario[] = [
  {
    id: 'suricata',
    title: 'Suricata: SYN flood on the infusion pump',
    description:
      'A Suricata EVE alert (severity 1) enters through /ingest/alerts and opens an incident on infusion-pump-01.',
    run: launchSuricata,
  },
  {
    id: 'wazuh',
    title: 'Wazuh: unauthorized MQTT publish to the ventilator',
    description:
      'A Wazuh alert (level 10) names the agent ventilator-01, so the device is identified by its registered name.',
    run: launchWazuh,
  },
  {
    id: 'pending',
    title: 'Pending approval: rotate ventilator credentials',
    description:
      'Opens an incident whose policy decision is waiting for a human. Approve it from the incident page; with signing required, the browser key signs it.',
    run: launchPendingApproval,
  },
]

function ScenarioCard({ scenario }: { scenario: Scenario }) {
  const queryClient = useQueryClient()
  const run = useMutation({
    mutationFn: () => scenario.run(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.incidents })
      queryClient.invalidateQueries({ queryKey: ['responses'] })
      queryClient.invalidateQueries({ queryKey: ['events'] })
    },
  })

  return (
    <div className={CARD}>
      <h3 className="font-medium">{scenario.title}</h3>
      <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{scenario.description}</p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          className={BUTTON}
          disabled={run.isPending}
          aria-label={`Launch scenario: ${scenario.title}`}
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Launching…' : 'Launch'}
        </button>
        {run.isError && (
          <span role="alert" className="text-sm text-red-600 dark:text-red-400">
            {describeError(run.error)}
          </span>
        )}
        {run.isSuccess && run.data.length === 0 && (
          <span className="text-sm text-gray-500">No incident was opened (alert ignored or rejected).</span>
        )}
        {run.isSuccess &&
          run.data.map((incidentId) => (
            <Link
              key={incidentId}
              to={`/incidents/${incidentId}`}
              className="text-sm font-medium text-cyber-700 underline dark:text-cyber-300"
            >
              {incidentId}
            </Link>
          ))}
      </div>
    </div>
  )
}

export function Demo() {
  const status = useDemoStatus()
  const reset = useDemoResetMutation()
  const [confirming, setConfirming] = useState(false)

  if (status.isLoading) {
    return <p className="text-sm text-gray-500">Checking demo mode…</p>
  }

  if (!status.data?.enabled) {
    return (
      <div className={CARD}>
        <h1 className="text-xl font-semibold">Demo mode is off</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          This server was not started with DEMO_MODE=true, so the demo tools are unavailable. That is the
          correct setting for any real deployment.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Demo mode</h1>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Start from a clean slate, then launch a scripted scenario. Everything runs through the real
          ingestion, policy and audit paths.
        </p>
      </div>

      <section className={CARD} aria-labelledby="reset-heading">
        <h2 id="reset-heading" className="font-medium">
          Reset
        </h2>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Removes all incidents, decisions, executed responses, agent traces, audit entries and events, and
          returns the simulated devices and patients to their starting state.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {!confirming ? (
            <button type="button" className={BUTTON} onClick={() => setConfirming(true)}>
              Reset demo data
            </button>
          ) : (
            <>
              <button
                type="button"
                className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                disabled={reset.isPending}
                onClick={() => {
                  reset.mutate(undefined, { onSettled: () => setConfirming(false) })
                }}
              >
                Yes, wipe everything
              </button>
              <button
                type="button"
                className="rounded-md border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700"
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
            </>
          )}
          {reset.isError && (
            <span role="alert" className="text-sm text-red-600 dark:text-red-400">
              {describeError(reset.error)}
            </span>
          )}
          {reset.isSuccess && (
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Removed {reset.data.incidents_removed} incidents, {reset.data.proposed_removed} pending decisions,{' '}
              {reset.data.executed_removed} executed responses and {reset.data.traces_removed} agent traces.
            </span>
          )}
        </div>
      </section>

      <section aria-labelledby="scenarios-heading" className="space-y-3">
        <h2 id="scenarios-heading" className="font-medium">
          Scenarios
        </h2>
        {SCENARIOS.map((scenario) => (
          <ScenarioCard key={scenario.id} scenario={scenario} />
        ))}
      </section>
    </div>
  )
}
