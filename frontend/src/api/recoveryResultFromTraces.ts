/**
 * Mirrors `riskAssessmentFromTraces.ts` for the last agent in the pipeline:
 * a successful `recovery_verification` trace's `output_payload` IS a real
 * `RecoveryResult` for this incident (including the `response_id` the agent
 * was actually given -- see that agent's own module docstring on why
 * `response_id` is an opaque caller-supplied reference rather than something
 * looked up from a store). `POST /recovery` takes exactly this shape, so
 * there is nothing to add or invent here -- just surface it, or say plainly
 * that recovery hasn't been verified yet.
 */

import { AGENT_LABELS } from '../agentLabels'
import type { AgentTrace, RecoveryResult } from './types'

export type RecoveryResultDerivation =
  | { result: RecoveryResult; missingSteps: [] }
  | { result: null; missingSteps: string[] }

export function deriveRecoveryResult(traces: AgentTrace[]): RecoveryResultDerivation {
  const trace = traces.find(
    (t) => t.agent_name === 'recovery_verification' && t.succeeded && t.output_payload !== null,
  )
  if (!trace) {
    return { result: null, missingSteps: [AGENT_LABELS.recovery_verification] }
  }
  return { result: trace.output_payload as unknown as RecoveryResult, missingSteps: [] }
}
