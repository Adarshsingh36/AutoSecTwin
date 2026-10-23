import { get, patch, post } from '../apiClient'
import type { ApprovalCreate, ApprovalDecisionRequest, ApprovalResponse } from '../types'

export const listApprovals = () => get<ApprovalResponse[]>('/approvals/')

export const createApproval = (payload: ApprovalCreate) =>
  post<ApprovalResponse>('/approvals/', payload)

export const decideApproval = (id: number, payload: ApprovalDecisionRequest) =>
  patch<ApprovalResponse>(`/approvals/${id}/decision`, payload)

export interface LegacyReviewItem {
  id: number
  legacy_profile_id: number
  status: string
  reason: string | null
  payload: Record<string, unknown> | null
  created_at: string
}

export interface HallucinationReviewItem {
  id: number
  vulnerability_id: number
  severity: string | null
  reason: string | null
  prediction_score: number | null
  validation_score: number | null
  created_at: string
}

export const listLegacyReviewQueue = () => get<LegacyReviewItem[]>('/approvals/legacy')

export const listHallucinationReviewQueue = () =>
  get<HallucinationReviewItem[]>('/approvals/hallucinations')
