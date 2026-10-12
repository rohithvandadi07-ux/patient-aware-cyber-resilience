/**
 * Builds a real `RiskAssessmentRequest` out of an incident's actual agent
 * traces -- never out of hand-written or synthetic data.
 *
 * Why this is safe: `app/agents/base.py`'s `run_agent_call` records
 * `output_payload = output.model_dump(mode="json")`, i.e. the exact Pydantic
 * model each agent produced, field for field. So a successful
 * `threat_reasoning` trace's `output_payload` IS a real `ThreatAssessment`
 * for this incident, a successful `healthcare_context` trace's is a real
 * `ClinicalContext`, and a successful `response_planning` trace's
 * `output_payload.candidate_actions` is the real `CandidateAction[]` that
 * agent proposed (architecture spec Section 11) -- not a list this frontend
 * invents to get something to show. `POST /risk-assessments` (the
 * deterministic L5 Risk Engine, Section 12) takes exactly these three
 * things, so this is the one place real inputs for it exist today, since no
 * orchestrator sequences the five agents automatically yet.
 *
 * When any of the three required traces is missing or failed, this returns
 * the names of what's missing instead of guessing -- the UI shows that
 * honestly rather than fabricating a score.
 */

import type { AgentName } from '../agentLabels'
import type { AgentTrace, CandidateAction, ClinicalContext, RiskAssessmentRequest, ThreatAssessment } from './types'

const REQUIRED_AGENTS = ['threat_reasoning', 'healthcare_context', 'response_planning'] as const satisfies readonly AgentName[]

function findSucceeded(traces: AgentTrace[], agentName: string): AgentTrace | undefined {
  return traces.find((trace) => trace.agent_name === agentName && trace.succeeded && trace.output_payload !== null)
}

export type RiskAssessmentDerivation =
  | { request: RiskAssessmentRequest; missingSteps: [] }
  | { request: null; missingSteps: AgentName[] }

export function deriveRiskAssessmentRequest(traces: AgentTrace[]): RiskAssessmentDerivation {
  const threatTrace = findSucceeded(traces, 'threat_reasoning')
  const contextTrace = findSucceeded(traces, 'healthcare_context')
  const planningTrace = findSucceeded(traces, 'response_planning')

  const missingSteps = REQUIRED_AGENTS.filter(
    (agent) => !{ threat_reasoning: threatTrace, healthcare_context: contextTrace, response_planning: planningTrace }[agent],
  )

  if (!threatTrace || !contextTrace || !planningTrace) {
    return { request: null, missingSteps }
  }

  // Safe per the module doc above: each trace's `output_payload` is the
  // real agent's own `model_dump(mode="json")` of exactly this schema.
  const threat = threatTrace.output_payload as unknown as ThreatAssessment
  const context = contextTrace.output_payload as unknown as ClinicalContext
  const proposedResponse = planningTrace.output_payload as unknown as { candidate_actions: CandidateAction[] }

  return {
    request: {
      threat,
      context,
      candidate_responses: proposedResponse.candidate_actions,
    },
    missingSteps: [],
  }
}
