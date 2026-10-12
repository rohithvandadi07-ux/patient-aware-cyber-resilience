/**
 * React Query hooks over `client.ts`. Centralizing these (rather than
 * calling the client straight from components) is what lets every panel
 * share one cache -- e.g. running a scenario invalidates the incident list
 * every panel that lists incidents is reading from, instead of each one
 * needing its own manual refetch wiring.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as client from './client'
import { ApiError } from './client'
import type {
  ExecuteResponseRequest,
  IncidentCreateRequest,
  ProposeResponseRequest,
  RecoveryResult,
  RiskAssessmentRequest,
} from './types'

export const queryKeys = {
  health: ['health'] as const,
  devices: ['devices'] as const,
  device: (deviceId: string) => ['devices', deviceId] as const,
  telemetry: (deviceId?: string) => ['telemetry', deviceId ?? null] as const,
  events: (deviceId?: string) => ['events', deviceId ?? null] as const,
  incidents: ['incidents'] as const,
  incident: (incidentId: string) => ['incidents', incidentId] as const,
  agentTraces: (incidentId: string) => ['agents', incidentId] as const,
  proposedResponse: (incidentId: string) => ['responses', 'proposed', incidentId] as const,
  executedResponses: (incidentId: string) => ['responses', 'executed', incidentId] as const,
  recoveryResults: (incidentId: string) => ['recovery', incidentId] as const,
  auditTrail: (incidentId: string) => ['blockchain', 'audit', incidentId] as const,
}

export function useDevices() {
  return useQuery({ queryKey: queryKeys.devices, queryFn: client.listDevices })
}

export function useIncidents() {
  return useQuery({ queryKey: queryKeys.incidents, queryFn: client.listIncidents })
}

export function useIncident(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.incident(incidentId),
    queryFn: () => client.getIncident(incidentId),
  })
}

export function useTelemetry(deviceId?: string) {
  return useQuery({
    queryKey: queryKeys.telemetry(deviceId),
    queryFn: () => client.listTelemetry(deviceId),
  })
}

export function useEvents(deviceId?: string) {
  return useQuery({
    queryKey: queryKeys.events(deviceId),
    queryFn: () => client.listEvents(deviceId),
  })
}

export function useAgentTraces(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.agentTraces(incidentId),
    queryFn: () => client.listAgentTracesForIncident(incidentId),
  })
}

/** 404 ("no proposed response pending for this incident") is a real,
 * expected state here -- not an error the UI should show as a failure --
 * so it resolves to `null` rather than rejecting. Any other failure still
 * rejects normally. */
export function useProposedResponse(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.proposedResponse(incidentId),
    queryFn: async () => {
      try {
        return await client.getProposedResponse(incidentId)
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          return null
        }
        throw error
      }
    },
  })
}

export function useExecutedResponses(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.executedResponses(incidentId),
    queryFn: () => client.listExecutedResponsesForIncident(incidentId),
  })
}

export function useRecoveryResults(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.recoveryResults(incidentId),
    queryFn: () => client.listRecoveryResultsForIncident(incidentId),
  })
}

export function useAuditTrail(incidentId: string) {
  return useQuery({
    queryKey: queryKeys.auditTrail(incidentId),
    queryFn: () => client.getAuditTrailForIncident(incidentId),
  })
}

export function useRunScenarioMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: client.runScenario,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.incidents })
      queryClient.invalidateQueries({ queryKey: ['telemetry'] })
      queryClient.invalidateQueries({ queryKey: ['events'] })
    },
  })
}

export function useCreateIncidentMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: IncidentCreateRequest) => client.createIncident(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.incidents }),
  })
}

export function useCalculateRiskMutation() {
  return useMutation({
    mutationFn: (body: RiskAssessmentRequest) => client.calculateRisk(body),
  })
}

export function useProposeResponseMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ProposeResponseRequest) => client.proposeResponse(body),
    onSuccess: (decision) =>
      queryClient.invalidateQueries({ queryKey: queryKeys.proposedResponse(decision.incident_id) }),
  })
}

export function useExecuteResponseMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ExecuteResponseRequest) => client.executeResponse(body),
    onSuccess: (executed) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.proposedResponse(executed.incident_id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.executedResponses(executed.incident_id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.auditTrail(executed.incident_id) })
    },
  })
}

export function useProcessRecoveryResultMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: RecoveryResult) => client.processRecoveryResult(body),
    onSuccess: (incident) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.incident(incident.incident_id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.recoveryResults(incident.incident_id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.auditTrail(incident.incident_id) })
    },
  })
}

export function useProcessOutboxMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: client.processPendingOutboxEntries,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['blockchain', 'audit'] }),
  })
}
