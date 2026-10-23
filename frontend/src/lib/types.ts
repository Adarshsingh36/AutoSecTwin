/**
 * Types transcribed directly from the live backend OpenAPI schema
 * (python -c "from main import app; app.openapi()"), not guessed.
 * Keep these in sync with api/schemas/autosectwin.py -- if a field is
 * added/renamed there, it must change here too.
 */

// ---------------------------------------------------------------------
// Twins
// ---------------------------------------------------------------------

export interface TwinProvisionRequest {
  vulnerability_id: number
  ttl_seconds?: number | null
}

export interface TwinProvisionResponse {
  id: number
  asset_id: number | null
  external_twin_id: number | null
  external_uuid: string | null
  name: string
  provider: string
  status: string
  environment: string | null
  ip_address: string | null
  network: string | null
  twin_image: string | null
  vm_name: string | null
  health: string | null
  legacy_flag: string | null
  endpoint: string | null
  destroy_at: string | null
  created_at: string
}

export interface TwinDestroyResponse {
  id: number
  status: string
  destroyed: boolean
  message: string
}

// ---------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------

export interface VulnerabilityCreate {
  asset_id?: number | null
  cve_id: string
  title?: string | null
  description?: string | null
  cvss_score?: number
  epss_score?: number
  severity?: string
  exposure_score?: number
  asset_criticality?: number
  kev_listed?: boolean
  metadata_json?: Record<string, unknown> | null
}

export interface VulnerabilityResponse extends VulnerabilityCreate {
  id: number
  exploitability_probability: number
  threat_intelligence_score: number
  created_at: string
}

// ---------------------------------------------------------------------
// Exploits
// ---------------------------------------------------------------------

export interface ExploitResponse {
  id: number
  vulnerability_id: number
  source: string
  external_id: string | null
  module_name: string | null
  title: string
  description: string | null
  reliability_score: number
  requires_auth: boolean
  metadata_json: Record<string, unknown> | null
  created_at: string
}

// ---------------------------------------------------------------------
// Validations
// ---------------------------------------------------------------------

export interface ValidationResponse {
  id: number
  vulnerability_id: number
  exploit_id: number | null
  twin_id: number | null
  evidence: Record<string, unknown> | null
  status: string
  validation_score: number
  phase: string
  analysis: string | null
  created_at: string
}

// ---------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------

export interface RecommendationGenerateRequest {
  vulnerability_id: number
  recommendation_type?: string
  context?: Record<string, unknown> | null
}

export interface RecommendationResponse {
  id: number
  vulnerability_id: number
  recommendation_type: string
  title: string
  content: string
  provider: string
  metadata_json: Record<string, unknown> | null
  created_at: string
}

// ---------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------

export interface ApprovalCreate {
  vulnerability_id: number
  recommendation_id?: number | null
  target_twin_id?: number | null
  fixed_version?: string | null
  requested_action: string
  requested_by?: string | null
  context?: Record<string, unknown> | null
}

export interface ApprovalDecisionRequest {
  status: 'approved' | 'rejected'
  decided_by: string
  decision_reason?: string | null
}

export interface ApprovalResponse extends ApprovalCreate {
  id: number
  status: string
  remediation_id: number | null
  decided_by: string | null
  decision_reason: string | null
  created_at: string
  decided_at: string | null
}

// ---------------------------------------------------------------------
// Remediations
// ---------------------------------------------------------------------

export interface RemediationCreate {
  vulnerability_id: number
  recommendation_id?: number | null
  target_twin_id?: number | null
  action: string
  applied_by?: string | null
}

export interface RemediationExecuteRequest {
  fixed_version: string
  run_revalidation?: boolean
}

export interface RemediationResponse extends RemediationCreate {
  id: number
  status: string
  executor: string | null
  handler: string | null
  execution_authorized: boolean
  target_modified: boolean
  verification_score: number
  evidence: Record<string, unknown> | null
  created_at: string
  execution_started_at: string | null
  execution_completed_at: string | null
}

export const REMEDIATION_IN_PROGRESS = new Set(['queued', 'executing', 'revalidating'])
export const REMEDIATION_TERMINAL = new Set(['verified', 'failed', 'manual_action_required'])

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

export interface ReportResponse {
  id: number
  vulnerability_id: number | null
  report_type: string
  title: string
  format: string
  metadata_json: Record<string, unknown> | null
  content: string
  created_at: string
}

// ---------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------

export interface OrchestrationRunRequest {
  vulnerability_id: number
  ttl_seconds?: number | null
}

export interface OrchestrationJobResponse {
  id: number
  vulnerability_id: number
  job_type: string
  status: string
  dispatch_backend: string | null
  celery_task_id: string | null
  result_summary: Record<string, unknown> | null
  error_message: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

// ---------------------------------------------------------------------
// Code-change remediation
// ---------------------------------------------------------------------

export interface CodeChangeProposeRequest {
  vulnerability_id: number
  file_path: string
  function_name: string
  requested_by?: string | null
}

export interface CodeChangeProposalResponse {
  approval_id: number
  file_path: string
  function_name: string
  current_code: string
  proposed_code: string
  diff: string
  explanation: string
  requires_manual_authoring: boolean
  content_hash: string
}

export interface CodeChangeApplyRequest {
  confirmed_content_hash: string
}

export interface CodeChangeApplyResponse {
  approval_id: number
  applied: boolean
  tests_passed: boolean | null
  test_output: string
  rolled_back: boolean
  file_path: string
}

// ---------------------------------------------------------------------
// Trust / Legacy / Confidence (System Health)
// ---------------------------------------------------------------------

export interface TrustStatisticsResponse {
  total_comparisons: number
  hallucinations: number
  agreement_rate: number
}

export interface DriftResponse {
  model_name: string
  drift_score: number
  baseline_agreement: number
  current_agreement: number
  retraining_recommended: boolean
  created_at: string
}
