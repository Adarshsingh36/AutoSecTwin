import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { PageShell } from '../components/layout/PageShell'
import { Button } from '../components/ui/Button'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { EmptyState, ErrorState, LoadingState, Unavailable } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { decideApproval, listApprovals } from '../lib/api/approvals'
import { executeRemediation, getRemediation, revalidateRemediation } from '../lib/api/remediations'
import { createClosedLoopReport } from '../lib/api/reports'
import { ApiError } from '../lib/apiClient'
import type { ApprovalResponse, RemediationResponse } from '../lib/types'
import { REMEDIATION_IN_PROGRESS } from '../lib/types'

function ApprovalRow({ approval, onSelect, selected }: { approval: ApprovalResponse; onSelect: () => void; selected: boolean }) {
  const fixedVersion = (approval.context?.fixed_version as string) ?? null
  return (
    <button
      onClick={onSelect}
      className={`w-full rounded-lg border p-4 text-left transition-colors ${
        selected ? 'border-neon-cyan bg-neon-cyan/5' : 'border-station-border hover:border-station-border/80 hover:bg-station-panel/40'
      }`}
    >
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-text-primary">Approval #{approval.id} · {approval.requested_action}</p>
          <p className="mt-0.5 text-xs text-text-muted">
            Vulnerability #{approval.vulnerability_id}
            {approval.target_twin_id ? ` · Twin #${approval.target_twin_id}` : ''}
            {fixedVersion ? ` · Fixed version: ${fixedVersion}` : ''}
          </p>
        </div>
        <StatusBadge status={approval.status} />
      </div>
    </button>
  )
}

export function Approvals() {
  const navigate = useNavigate()
  const { data: approvals, loading, error, refetch } = useAsync(listApprovals)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [decidedBy, setDecidedBy] = useState('')
  const [reason, setReason] = useState('')
  const [deciding, setDeciding] = useState(false)
  const [confirmReject, setConfirmReject] = useState(false)
  const [confirmExecute, setConfirmExecute] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null)
  const [remediationError, setRemediationError] = useState<string | null>(null)
  const [reportBusy, setReportBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const selected = approvals?.find((a) => a.id === selectedId) ?? null
  const reviewPackage = selected?.context?.review_package as Record<string, unknown> | undefined

  async function loadRemediation(id: number) {
    try {
      setRemediation(await getRemediation(id))
      setRemediationError(null)
    } catch (err) {
      setRemediationError(err instanceof ApiError ? err.detail : 'Could not load remediation status.')
    }
  }

  function selectApproval(a: ApprovalResponse) {
    setSelectedId(a.id)
    setActionError(null)
    setRemediation(null)
    if (a.remediation_id) loadRemediation(a.remediation_id)
  }

  async function handleDecision(status: 'approved' | 'rejected') {
    if (!selected) return
    if (!decidedBy.trim()) {
      setActionError('Enter your reviewer identity before deciding.')
      return
    }
    setDeciding(true)
    setActionError(null)
    try {
      await decideApproval(selected.id, { status, decided_by: decidedBy, decision_reason: reason || null })
      await refetch()
      setConfirmReject(false)
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : 'Decision failed.')
    } finally {
      setDeciding(false)
    }
  }

  async function handleExecute() {
    if (!selected?.remediation_id) return
    const fixedVersion = (selected.context?.fixed_version as string) ?? ''
    if (!fixedVersion) {
      setActionError('No fixed_version recorded on this approval; cannot execute.')
      return
    }
    setExecuting(true)
    try {
      const updated = await executeRemediation(selected.remediation_id, { fixed_version: fixedVersion, run_revalidation: true })
      setRemediation(updated)
      setConfirmExecute(false)
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : 'Execution request failed.')
    } finally {
      setExecuting(false)
    }
  }

  async function handleRevalidate() {
    if (!selected?.remediation_id) return
    setExecuting(true)
    try {
      setRemediation(await revalidateRemediation(selected.remediation_id))
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : 'Revalidation request failed.')
    } finally {
      setExecuting(false)
    }
  }

  async function handleGenerateReport() {
    if (!selected?.remediation_id) return
    setReportBusy(true)
    try {
      const report = await createClosedLoopReport(selected.remediation_id)
      navigate(`/reports/${report.id}`)
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : 'Report generation failed.')
    } finally {
      setReportBusy(false)
    }
  }

  return (
    <PageShell
      title="Security Operations — Human Approval Required"
      subtitle="Every remediation requires explicit human authorization before the target twin is destroyed and redeployed."
    >
      {loading && <LoadingState label="Retrieving approval queue..." />}
      {error && <ErrorState message={error} onRetry={refetch} />}

      {!loading && !error && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
          <div className="lg:col-span-2">
            {approvals && approvals.length > 0 ? (
              <div className="flex flex-col gap-3">
                {approvals.map((a) => (
                  <ApprovalRow key={a.id} approval={a} selected={a.id === selectedId} onSelect={() => selectApproval(a)} />
                ))}
              </div>
            ) : (
              <EmptyState title="No approval requests" description="Create one via POST /approvals/ or let the orchestration pipeline raise one for a validated vulnerability." />
            )}
          </div>

          <div className="lg:col-span-3">
            {!selected ? (
              <EmptyState title="Select an approval" description="Choose a request from the queue to review its evidence and decide." />
            ) : (
              <div className="panel panel-glow p-6">
                <div className="mb-4 flex items-center justify-between">
                  <h2 className="font-display text-base font-semibold text-text-primary">Approval #{selected.id}</h2>
                  <StatusBadge status={selected.status} />
                </div>

                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <dt className="text-text-muted">Vulnerability</dt>
                  <dd className="text-text-primary">#{selected.vulnerability_id} {reviewPackage?.cve_id ? `(${reviewPackage.cve_id})` : ''}</dd>
                  <dt className="text-text-muted">Target Twin</dt>
                  <dd className="text-text-primary">
                    {selected.target_twin_id ? (
                      <Link to="/twins" className="hover:text-neon-cyan hover:underline">#{selected.target_twin_id}</Link>
                    ) : <Unavailable />}
                  </dd>
                  <dt className="text-text-muted">Current Version</dt>
                  <dd className="text-text-primary">{(reviewPackage?.current_version as string) ?? <Unavailable />}</dd>
                  <dt className="text-text-muted">Fixed Version</dt>
                  <dd className="text-text-primary font-semibold text-neon-cyan">{(selected.context?.fixed_version as string) ?? <Unavailable />}</dd>
                  <dt className="text-text-muted">Requested By</dt>
                  <dd className="text-text-primary">{selected.requested_by ?? <Unavailable />}</dd>
                  <dt className="text-text-muted">Requested At</dt>
                  <dd className="text-text-primary">{new Date(selected.created_at).toLocaleString()}</dd>
                </dl>

                {reviewPackage?.limitations ? (
                  <div className="mt-4 rounded-lg border border-alert-warning/30 bg-alert-warning/5 p-3">
                    <p className="text-xs font-semibold uppercase tracking-wide text-alert-warning">Limitations</p>
                    <ul className="mt-1 list-inside list-disc text-xs text-text-muted">
                      {(reviewPackage.limitations as string[]).map((l, i) => <li key={i}>{l}</li>)}
                    </ul>
                  </div>
                ) : null}

                {selected.status === 'pending' && (
                  <div className="mt-5 border-t border-station-border pt-5">
                    <label className="mb-1 block text-xs font-medium text-text-muted">Reviewer identity *</label>
                    <input
                      value={decidedBy}
                      onChange={(e) => setDecidedBy(e.target.value)}
                      placeholder="your name or handle"
                      className="mb-3 w-full rounded-lg border border-station-border bg-station-void/60 px-3 py-2 text-sm text-text-primary focus:border-neon-cyan focus:outline-none"
                    />
                    <label className="mb-1 block text-xs font-medium text-text-muted">Decision reason (optional)</label>
                    <textarea
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      rows={2}
                      className="mb-3 w-full rounded-lg border border-station-border bg-station-void/60 px-3 py-2 text-sm text-text-primary focus:border-neon-cyan focus:outline-none"
                    />
                    <div className="flex gap-3">
                      <Button loading={deciding} onClick={() => handleDecision('approved')}>Approve</Button>
                      <Button variant="danger" onClick={() => setConfirmReject(true)}>Reject</Button>
                    </div>
                  </div>
                )}

                {selected.status === 'approved' && selected.remediation_id && (
                  <div className="mt-5 border-t border-station-border pt-5">
                    <h3 className="mb-3 font-display text-sm font-semibold text-text-primary">Remediation #{selected.remediation_id}</h3>
                    {remediationError && <ErrorState message={remediationError} />}
                    {remediation && (
                      <>
                        <div className="mb-3 flex items-center gap-2">
                          <span className="text-xs text-text-muted">Status:</span>
                          <StatusBadge status={remediation.status} />
                          {REMEDIATION_IN_PROGRESS.has(remediation.status) && (
                            <Button variant="ghost" onClick={() => loadRemediation(remediation.id)}>Refresh</Button>
                          )}
                        </div>
                        {remediation.evidence?.before_after ? (
                          <pre className="mb-3 max-h-48 overflow-auto rounded-lg bg-station-void/60 p-3 text-xs text-text-muted">
                            {JSON.stringify(remediation.evidence.before_after, null, 2)}
                          </pre>
                        ) : null}
                      </>
                    )}
                    <div className="flex flex-wrap gap-3">
                      {(!remediation || remediation.status === 'approved' || remediation.status === 'failed' || remediation.status === 'manual_action_required') && (
                        <Button variant="danger" onClick={() => setConfirmExecute(true)}>Execute Remediation</Button>
                      )}
                      {remediation && (remediation.status === 'executed' || remediation.status === 'manual_action_required' || remediation.status === 'failed') && (
                        <Button loading={executing} onClick={handleRevalidate}>Revalidate</Button>
                      )}
                      {remediation && (remediation.status === 'verified' || remediation.status === 'failed') && (
                        <Button variant="secondary" loading={reportBusy} onClick={handleGenerateReport}>Generate Report</Button>
                      )}
                    </div>
                  </div>
                )}

                {actionError && <p className="mt-4 text-sm text-alert-critical">{actionError}</p>}
              </div>
            )}
          </div>
        </div>
      )}

      <ConfirmDialog
        open={confirmReject}
        title="Reject this approval?"
        description="No remediation will be created. This action is recorded with your reviewer identity and reason."
        danger
        loading={deciding}
        confirmLabel="Reject"
        onConfirm={() => handleDecision('rejected')}
        onCancel={() => setConfirmReject(false)}
      />

      <ConfirmDialog
        open={confirmExecute}
        title="Execute remediation — destructive action"
        description={
          <>
            This will <strong>destroy the current vulnerable Digital Twin</strong> and redeploy it at the approved
            fixed version. The backend will then re-run the original exploit to independently verify the fix. This
            cannot be undone from this interface.
          </>
        }
        danger
        loading={executing}
        confirmLabel="Destroy & Redeploy"
        onConfirm={handleExecute}
        onCancel={() => setConfirmExecute(false)}
      />
    </PageShell>
  )
}
