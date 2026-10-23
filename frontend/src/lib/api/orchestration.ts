import { get, post } from '../apiClient'
import type { OrchestrationJobResponse, OrchestrationRunRequest } from '../types'

export const runOrchestration = (payload: OrchestrationRunRequest) =>
  post<OrchestrationJobResponse>('/orchestration/run', payload)

export const listOrchestrationJobs = (vulnerabilityId?: number) =>
  get<OrchestrationJobResponse[]>(
    vulnerabilityId ? `/orchestration/jobs?vulnerability_id=${vulnerabilityId}` : '/orchestration/jobs',
  )

export const getOrchestrationJob = (id: number) =>
  get<OrchestrationJobResponse>(`/orchestration/jobs/${id}`)
