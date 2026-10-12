import type { AgentTrace, InvestigationReport } from '../api/types'

/**
 * The Investigation agent's own output, verbatim -- the only "evidence"
 * this incident has is whatever `app/agents/investigation.py` actually
 * produced and recorded as a trace (architecture spec Section 11:
 * `InvestigationReport {evidence, timeline, affected_devices, observations,
 * confidence}`). No investigation trace means no evidence has been
 * gathered yet, shown plainly rather than left blank.
 */
export function EvidencePanel({ traces }: { traces: AgentTrace[] }) {
  const trace = [...traces]
    .filter((t) => t.agent_name === 'investigation' && t.succeeded && t.output_payload !== null)
    .sort((a, b) => new Date(b.recorded_at).getTime() - new Date(a.recorded_at).getTime())[0]

  if (!trace) {
    return <p className="text-sm text-gray-500 dark:text-gray-400">Not yet investigated.</p>
  }

  const report = trace.output_payload as unknown as InvestigationReport

  return (
    <div className="space-y-3 text-sm">
      <p>
        <span className="font-medium text-gray-500 dark:text-gray-400">Confidence: </span>
        {Math.round(report.confidence * 100)}%
      </p>
      <div>
        <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Affected devices</p>
        <p>{report.affected_devices.join(', ') || 'none'}</p>
      </div>
      <div>
        <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Evidence</p>
        <ul className="list-inside list-disc space-y-0.5">
          {report.evidence.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      </div>
      <div>
        <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Timeline</p>
        <ul className="list-inside list-disc space-y-0.5">
          {report.timeline.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      </div>
      <div>
        <p className="mb-1 font-medium text-gray-500 dark:text-gray-400">Observations</p>
        <ul className="list-inside list-disc space-y-0.5">
          {report.observations.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}
