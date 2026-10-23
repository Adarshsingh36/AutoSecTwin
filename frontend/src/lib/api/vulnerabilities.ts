import { get, post } from '../apiClient'
import type { VulnerabilityCreate, VulnerabilityResponse } from '../types'

export const listVulnerabilities = () => get<VulnerabilityResponse[]>('/vulnerabilities/')

export const getVulnerability = (id: number) => get<VulnerabilityResponse>(`/vulnerabilities/${id}`)

export const createVulnerability = (payload: VulnerabilityCreate) =>
  post<VulnerabilityResponse>('/vulnerabilities/', payload)
