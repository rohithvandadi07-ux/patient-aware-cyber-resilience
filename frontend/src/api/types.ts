/**
 * TypeScript mirrors of the backend's Pydantic schemas (`backend/app/schemas/`)
 * and view models (`backend/app/api/agents.py`'s `AgentTraceOut`,
 * `backend/app/api/blockchain_audit.py`'s `OutboxEntryOut`).
 *
 * Hand-maintained, not generated from the OpenAPI schema -- the API surface
 * (12 routers, Phase 9) is still small enough to keep in sync by eye, and a
 * codegen step is its own piece of tooling to introduce, run, and trust.
 * Field names and types below match the backend exactly, including which
 * fields are nullable (`| null`, never silently defaulted) -- the backend's
 * own anti-fabrication rule ("a record with chain_tx_id IS NULL means 'not
 * yet committed' ... never silently hidden") only holds end to end if this
 * layer doesn't quietly turn a null into an empty string or a zero.
 */

// --- enums (app/schemas/enums.py) ---

export type DeviceCriticality = 'low' | 'medium' | 'high'

export type ImpactLevel = 'low' | 'medium' | 'high' | 'critical'

export type AttackCategory =
  | 'dos'
  | 'ddos'
  | 'reconnaissance'
  | 'mqtt_based'
  | 'spoofing'
  | 'mitm_injection'
  | 'unknown'

export type ResponseActionCategory =
  | 'block_traffic'
  | 'revoke_session'
  | 'rotate_credentials'
  | 'restrict_communication'
  | 'isolate_non_critical'
  | 'isolate_critical'
  | 'quarantine_segment'
  | 'activate_backup'
  | 'restart_service'
  | 'failover'
  | 'shutdown'

export type ApprovalDecision = 'approved' | 'rejected'

export type IncidentStatus =
  | 'detected'
  | 'investigating'
  | 'risk_assessed'
  | 'awaiting_approval'
  | 'response_executing'
  | 'recovery_verifying'
  | 'resolved'
  | 'reopened'
  | 'investigation_stalled'
  | 'threat_reasoning_stalled'
  | 'context_stalled'
  | 'response_planning_stalled'
  | 'recovery_verification_stalled'

export type OutboxRecordType = 'incident' | 'decision' | 'approval' | 'response' | 'recovery'

export type OutboxStatus = 'pending' | 'confirmed' | 'failed'

// --- app/schemas/device.py ---

export type DeviceType = 'infusion_pump' | 'ventilator' | 'ecg_monitor'

export type OperationalState = 'idle' | 'active' | 'alarm' | 'isolated' | 'off'

export interface DeviceState {
  device_id: string
  device_type: DeviceType
  criticality: DeviceCriticality
  patient_dependency: boolean
  synthetic_patient_id: string | null
  operational_state: OperationalState
  network_state: string
}

// --- app/schemas/telemetry.py / events.py ---

export interface TelemetryReading {
  device_id: string
  timestamp: string
  readings: Record<string, number>
}

export interface NetworkEvent {
  device_id: string
  timestamp: string
  event_type: string
  source: string
  payload: Record<string, string>
  is_attack_injection: boolean
}

// --- app/schemas/incident.py ---

export interface Incident {
  incident_id: string
  device_id: string
  status: IncidentStatus
  created_at: string
  updated_at: string
  chain_tx_id: string | null
}

// --- app/schemas/detection.py ---

export interface DetectionEvent {
  device_id: string
  attack_type: AttackCategory
  confidence: number
  severity_hint: ImpactLevel
  timestamp: string
  evidence_ref: string
}

// --- app/schemas/agents.py ---

export interface InvestigationReport {
  incident_id: string
  evidence: string[]
  timeline: string[]
  affected_devices: string[]
  observations: string[]
  confidence: number
}

export interface ThreatAssessment {
  incident_id: string
  attack_type: AttackCategory
  severity: ImpactLevel
  confidence: number
  propagation_risk: ImpactLevel
  reasoning_summary: string
}

export interface ClinicalContext {
  incident_id: string
  device_criticality: DeviceCriticality
  patient_dependency: boolean
  clinical_impact_level: ImpactLevel
  safety_constraints: string[]
}

export interface CandidateAction {
  action_category: ResponseActionCategory
  description: string
}

export interface ProposedResponse {
  incident_id: string
  candidate_actions: CandidateAction[]
  security_benefit: Record<string, number>
  clinical_impact: Record<string, ImpactLevel>
  recommended_action: ResponseActionCategory
  rationale: string
}

export interface RecoveryResult {
  incident_id: string
  response_id: string
  containment_verified: boolean
  residual_threats: string[]
  recovery_succeeded: boolean
  reinvestigation_required: boolean
}

// --- app/schemas/risk.py ---

export interface RiskScore {
  incident_id: string
  cyber_risk: number
  clinical_risk: number
  response_impact: Record<string, ImpactLevel>
  explanation: string
}

// --- app/schemas/policy.py ---

/** A candidate action the Policy Engine considered but did not choose, routed by the same rules. */
export interface AlternativeAction {
  action: ResponseActionCategory
  response_impact: ImpactLevel
  requires_human_approval: boolean
  policy_rule_id: string
  security_benefit: number | null
}

export interface PolicyDecision {
  incident_id: string
  chosen_action: ResponseActionCategory
  requires_human_approval: boolean
  policy_rule_id: string
  rationale: string
  /** Ranked: autonomous before approval-required, then lower impact, then higher benefit. */
  alternatives?: AlternativeAction[]
}

// --- app/schemas/response.py ---

export interface ApprovalRecord {
  incident_id: string
  approver_identity: string
  decision: ApprovalDecision
  timestamp: string
  notes: string | null
}

export interface ExecutedResponse {
  incident_id: string
  action_taken: ResponseActionCategory
  executed_by: string
  timestamp: string
  chain_tx_id: string | null
}

// --- app/api/agents.py: AgentTraceOut ---

export interface AgentTrace {
  incident_id: string
  agent_name: string
  input_payload: Record<string, unknown>
  output_payload: Record<string, unknown> | null
  succeeded: boolean
  recorded_at: string
  error: string | null
}

// --- app/api/blockchain_audit.py: OutboxEntryOut ---

export interface OutboxEntry {
  id: number
  record_type: OutboxRecordType
  payload: Record<string, unknown>
  created_at: string
  status: OutboxStatus
  chain_tx_id: string | null
  attempts: number
  last_error: string | null
  updated_at: string
}

// --- app/api/health.py ---

export interface HealthStatus {
  status: string
  service: string
}

// --- request bodies the backend routers expect (app/api/*.py) ---

export interface IncidentCreateRequest {
  incident_id: string
  device_id: string
  attack_type: AttackCategory
  evidence_ref: string
  timestamp: string
}

export interface RiskAssessmentRequest {
  threat: ThreatAssessment
  context: ClinicalContext
  candidate_responses: CandidateAction[]
}

export interface ProposeResponseRequest {
  risk_score: RiskScore
  proposed_response: ProposedResponse
  context: ClinicalContext
}

export interface ExecuteResponseRequest {
  incident_id: string
  approval?: ApprovalRecord | null
}
