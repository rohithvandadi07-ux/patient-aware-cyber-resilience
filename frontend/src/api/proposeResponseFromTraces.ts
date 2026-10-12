/**
 * Builds a real `ProposeResponseRequest` the same way `riskAssessmentFromTraces.ts`
 * builds a risk-assessment request: from the incident's actual agent traces
 * plus a real, already-computed `RiskScore` -- never synthetic data.
 *
 * `POST /responses/proposed` (the Policy Engine, L6, Section 7 step 9) takes
 * a `RiskScore`, the `ProposedResponse` the Response Planning agent produced,
 * and the `ClinicalContext` the Clinical Context agent produced. The risk
 * score has no persistence of its own (see `riskAssessmentFromTraces.ts`),
 * so it's threaded through as a parameter -- the caller (`IncidentDetail`)
 * is the one place that already holds the result of a real `/risk-assessments`
 * call for this incident.
 */

import { AGENT_LABELS, type AgentName } from '../agentLabels'
import type { AgentTrace, ClinicalContext, ProposedResponse, ProposeResponseRequest, RiskScore } from './types'

function findSucceeded(traces: AgentTrace[], agentName: AgentName): AgentTrace | undefined {
  return traces.find((trace) => trace.agent_name === agentName && trace.succeeded && trace.output_payload !== null)
}

export type ProposeResponseDerivation =
  | { request: ProposeResponseRequest; missingSteps: [] }
  | { request: null; missingSteps: string[] }

export function deriveProposeResponseRequest(
  traces: AgentTrace[],
  riskScore: RiskScore | null,
): ProposeResponseDerivation {
  const contextTrace = findSucceeded(traces, 'healthcare_context')
  const planningTrace = findSucceeded(traces, 'response_planning')

  const missingSteps: string[] = []
  if (!riskScore) missingSteps.push('a risk assessment for this incident')
  if (!contextTrace) missingSteps.push(AGENT_LABELS.healthcare_context)
  if (!planningTrace) missingSteps.push(AGENT_LABELS.response_planning)

  if (!riskScore || !contextTrace || !planningTrace) {
    return { request: null, missingSteps }
  }

  // Safe per `riskAssessmentFromTraces.ts`'s module doc: a successful
  // trace's `output_payload` is the real agent's own full model dump.
  const context = contextTrace.output_payload as unknown as ClinicalContext
  const proposedResponse = planningTrace.output_payload as unknown as ProposedResponse

  return {
    request: { risk_score: riskScore, proposed_response: proposedResponse, context },
    missingSteps: [],
  }
}
