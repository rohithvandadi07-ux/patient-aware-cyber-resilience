import type { IncidentStatus } from '../api/types'

const STATUS_STYLES: Record<IncidentStatus, string> = {
  detected: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  investigating: 'bg-cyber-100 text-cyber-700 dark:bg-cyber-900 dark:text-cyber-300',
  risk_assessed: 'bg-cyber-100 text-cyber-700 dark:bg-cyber-900 dark:text-cyber-300',
  awaiting_approval: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  response_executing: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  recovery_verifying: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  resolved: 'bg-clinical-100 text-clinical-700 dark:bg-clinical-900 dark:text-clinical-300',
  reopened: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  investigation_stalled: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
  threat_reasoning_stalled: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
  context_stalled: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
  response_planning_stalled: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
  recovery_verification_stalled: 'bg-danger-100 text-danger-700 dark:bg-red-950 dark:text-red-300',
}

/** Human-readable label -- `"awaiting_approval"` -> `"Awaiting approval"` --
 * derived mechanically from the status value, never a hand-maintained
 * second copy of the enum that could drift from the backend's. */
function humanize(status: string): string {
  const spaced = status.replaceAll('_', ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
    >
      {humanize(status)}
    </span>
  )
}
