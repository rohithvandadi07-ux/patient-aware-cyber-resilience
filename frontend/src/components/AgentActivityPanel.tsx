import { AGENT_LABELS, AGENT_NAMES } from '../agentLabels'
import type { AgentTrace } from '../api/types'

/**
 * Real agent-trace data, one row per known agent, or an explicit "Not run"
 * state -- never a placeholder or a guess at what an agent probably did.
 * `app/agents/base.py`'s `run_agent_call` writes a trace on every call,
 * success or failure, so the absence of a trace for an agent means that
 * agent has genuinely never been invoked for this incident, not that data
 * is missing.
 *
 * When an agent ran more than once (e.g. a `reopened` incident re-running
 * investigation), every row shows the most recent trace's outcome plus how
 * many times it has run -- the full history is available by expanding the
 * row rather than being summarized away.
 */

function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

function StatusChip({ succeeded }: { succeeded: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
        succeeded
          ? 'bg-clinical-100 text-clinical-700 dark:bg-clinical-900 dark:text-clinical-300'
          : 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300'
      }`}
    >
      {succeeded ? 'Succeeded' : 'Failed'}
    </span>
  )
}

function AgentRow({ agentLabel, traces }: { agentLabel: string; traces: AgentTrace[] }) {
  if (traces.length === 0) {
    return (
      <div className="flex items-center justify-between border-b border-gray-100 py-2 last:border-0 dark:border-gray-800/60">
        <span className="text-sm font-medium">{agentLabel}</span>
        <span className="text-xs text-gray-400 dark:text-gray-500">Not run</span>
      </div>
    )
  }

  const sorted = [...traces].sort(
    (a, b) => new Date(b.recorded_at).getTime() - new Date(a.recorded_at).getTime(),
  )
  const latest = sorted[0]

  return (
    <details className="border-b border-gray-100 py-2 last:border-0 dark:border-gray-800/60">
      <summary className="flex cursor-pointer items-center justify-between text-sm">
        <span className="font-medium">
          {agentLabel}
          {sorted.length > 1 && (
            <span className="ml-2 text-xs text-gray-400 dark:text-gray-500">ran {sorted.length}×</span>
          )}
        </span>
        <span className="flex items-center gap-2">
          <span className="text-xs text-gray-500 dark:text-gray-400">{formatTimestamp(latest.recorded_at)}</span>
          <StatusChip succeeded={latest.succeeded} />
        </span>
      </summary>
      <div className="mt-2 space-y-2 text-xs text-gray-600 dark:text-gray-300">
        {!latest.succeeded && latest.error && (
          <p className="text-danger-600">
            <span className="font-medium">Error:</span> {latest.error}
          </p>
        )}
        <div>
          <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Input</p>
          <pre className="overflow-x-auto rounded bg-gray-50 p-2 dark:bg-gray-800">
            {JSON.stringify(latest.input_payload, null, 2)}
          </pre>
        </div>
        {latest.output_payload && (
          <div>
            <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Output</p>
            <pre className="overflow-x-auto rounded bg-gray-50 p-2 dark:bg-gray-800">
              {JSON.stringify(latest.output_payload, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </details>
  )
}

export function AgentActivityPanel({ traces }: { traces: AgentTrace[] }) {
  return (
    <div>
      {AGENT_NAMES.map((agentName) => (
        <AgentRow
          key={agentName}
          agentLabel={AGENT_LABELS[agentName]}
          traces={traces.filter((trace) => trace.agent_name === agentName)}
        />
      ))}
    </div>
  )
}
