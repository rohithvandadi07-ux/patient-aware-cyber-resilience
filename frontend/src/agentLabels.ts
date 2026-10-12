/**
 * The five real agents (architecture spec Section 11), in pipeline order,
 * with the human-readable name each one's `agent_name` trace field maps to.
 * Kept in one place so the Agent Activity panel and the dual-risk panel's
 * "what's missing" message never drift into two different spellings of the
 * same agent.
 */

export const AGENT_NAMES = [
  'investigation',
  'threat_reasoning',
  'healthcare_context',
  'response_planning',
  'recovery_verification',
] as const

export type AgentName = (typeof AGENT_NAMES)[number]

export const AGENT_LABELS: Record<AgentName, string> = {
  investigation: 'Investigation agent',
  threat_reasoning: 'Threat Reasoning agent',
  healthcare_context: 'Clinical Context agent',
  response_planning: 'Response Planning agent',
  recovery_verification: 'Recovery Verification agent',
}
