import { post } from '../apiClient'
import type {
  CodeChangeApplyRequest,
  CodeChangeApplyResponse,
  CodeChangeProposalResponse,
  CodeChangeProposeRequest,
} from '../types'

export const proposeCodeChange = (payload: CodeChangeProposeRequest) =>
  post<CodeChangeProposalResponse>('/code-remediation/propose', payload)

export const applyCodeChange = (approvalId: number, payload: CodeChangeApplyRequest) =>
  post<CodeChangeApplyResponse>(`/code-remediation/${approvalId}/apply`, payload)
