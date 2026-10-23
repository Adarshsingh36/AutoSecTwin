import { get, post } from '../apiClient'
import type { RemediationCreate, RemediationExecuteRequest, RemediationResponse } from '../types'

export const listRemediations = () => get<RemediationResponse[]>('/remediations/')

export const getRemediation = (id: number) => get<RemediationResponse>(`/remediations/${id}`)

export const createRemediation = (payload: RemediationCreate) =>
  post<RemediationResponse>('/remediations/', payload)

export const executeRemediation = (id: number, payload: RemediationExecuteRequest) =>
  post<RemediationResponse>(`/remediations/${id}/execute`, payload)

export const revalidateRemediation = (id: number) =>
  post<RemediationResponse>(`/remediations/${id}/revalidate`)
