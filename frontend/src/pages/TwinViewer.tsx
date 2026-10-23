import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { PageShell } from '../components/layout/PageShell'
import { Button } from '../components/ui/Button'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { ErrorState, LoadingState, Unavailable } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { destroyTwin, getTwin } from '../lib/api/twins'
import { ApiError } from '../lib/apiClient'

export function TwinViewer() {
  const { id } = useParams()
  const twinId = Number(id)
  const { data: twin, loading, error, refetch } = useAsync(() => getTwin(twinId), [twinId])
  const [fullscreen, setFullscreen] = useState(false)
  const [confirmDestroy, setConfirmDestroy] = useState(false)
  const [destroying, setDestroying] = useState(false)
  const [destroyError, setDestroyError] = useState<string | null>(null)

  async function handleDestroy() {
    setDestroying(true)
    try {
      await destroyTwin(twinId)
      await refetch()
      setConfirmDestroy(false)
    } catch (err) {
      setDestroyError(err instanceof ApiError ? err.detail : 'Destroy request failed.')
    } finally {
      setDestroying(false)
    }
  }

  if (loading) return <PageShell title="Digital Twin"><LoadingState label="Establishing uplink to twin..." /></PageShell>
  if (error) return <PageShell title="Digital Twin"><ErrorState message={error} onRetry={refetch} /></PageShell>
  if (!twin) return null

  const isLive = twin.status !== 'destroyed' && twin.external_twin_id !== null
  const isManaged = twin.provider === 'TwinGenerator'

  return (
    <PageShell
      title={twin.name}
      subtitle={`Twin #${twin.id}${twin.external_uuid ? ` · ${twin.external_uuid}` : ''}`}
      actions={
        <>
          <Link to="/twins"><Button variant="ghost">Back to Fleet</Button></Link>
          <Button variant="secondary" onClick={() => setFullscreen(true)}>Enter Full-Screen</Button>
          {isLive && (
            <Button variant="danger" onClick={() => setConfirmDestroy(true)}>Destroy Twin</Button>
          )}
        </>
      }
    >
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="panel panel-glow flex flex-col items-center justify-center gap-4 p-10 lg:col-span-1">
          <div
            className={`relative flex h-32 w-32 items-center justify-center rounded-full border-2 ${
              twin.health === 'healthy' ? 'border-verified-green' : twin.health === 'unhealthy' ? 'border-alert-critical' : 'border-neon-blue'
            }`}
            style={{ animation: isLive ? 'pulse-glow 2.4s ease-in-out infinite' : undefined }}
          >
            <div className="absolute inset-2 rounded-full border border-station-border" />
            <span className="font-display text-3xl">{twin.environment === 'docker' ? '🐳' : twin.environment === 'vm' ? '🖥️' : '◌'}</span>
          </div>
          <StatusBadge status={twin.health ?? twin.status} className="text-sm" />
          <p className="text-center text-xs text-text-muted">
            {isManaged ? 'Managed by AutoSecTwin\u2019s Digital Twin Generator' : `Provider: ${twin.provider}`}
            {!isLive && ' — this twin is no longer live.'}
          </p>
        </div>

        <div className="panel p-6 lg:col-span-2">
          <h2 className="mb-4 font-display text-sm font-semibold uppercase tracking-wider text-text-muted">Twin Identity</h2>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <dt className="text-text-muted">Status</dt>
            <dd><StatusBadge status={twin.status} /></dd>
            <dt className="text-text-muted">Environment</dt>
            <dd className="text-text-primary">{twin.environment ?? <Unavailable />}</dd>
            <dt className="text-text-muted">Docker Image / VM</dt>
            <dd className="font-mono text-text-primary">{twin.twin_image ?? twin.vm_name ?? <Unavailable />}</dd>
            <dt className="text-text-muted">Network</dt>
            <dd className="text-text-primary">{twin.network ?? <Unavailable />}</dd>
            <dt className="text-text-muted">IP Address</dt>
            <dd className="font-mono text-text-primary">{twin.ip_address ?? <Unavailable />}</dd>
            <dt className="text-text-muted">Endpoint</dt>
            <dd className="font-mono text-text-primary">{twin.endpoint ?? <Unavailable />}</dd>
            <dt className="text-text-muted">External Twin ID</dt>
            <dd className="text-text-primary">{twin.external_twin_id ?? <Unavailable />}</dd>
            <dt className="text-text-muted">Legacy Flag</dt>
            <dd className="text-text-primary">{twin.legacy_flag ?? <Unavailable />}</dd>
            <dt className="text-text-muted">Created</dt>
            <dd className="text-text-primary">{new Date(twin.created_at).toLocaleString()}</dd>
            <dt className="text-text-muted">Scheduled Destroy</dt>
            <dd className="text-text-primary">{twin.destroy_at ? new Date(twin.destroy_at).toLocaleString() : <Unavailable />}</dd>
          </dl>
        </div>
      </div>

      {destroyError && <p className="mt-4 text-sm text-alert-critical">{destroyError}</p>}

      <ConfirmDialog
        open={confirmDestroy}
        title="Destroy this Digital Twin?"
        description="This permanently tears down the twin's container/VM and isolated network via the Digital Twin Generator. This cannot be undone."
        danger
        loading={destroying}
        confirmLabel="Destroy Twin"
        onConfirm={handleDestroy}
        onCancel={() => setConfirmDestroy(false)}
      />

      {fullscreen && (
        <div className="fixed inset-0 z-50 flex flex-col bg-station-void p-8">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="font-display text-lg font-bold text-text-primary">{twin.name} — Full-Screen View</h2>
            <Button variant="ghost" onClick={() => setFullscreen(false)}>Exit Full-Screen ✕</Button>
          </div>
          <div className="flex flex-1 items-center justify-center">
            <div
              className={`flex h-72 w-72 items-center justify-center rounded-full border-4 ${
                twin.health === 'healthy' ? 'border-verified-green' : 'border-neon-blue'
              }`}
              style={{ animation: 'pulse-glow 2.4s ease-in-out infinite' }}
            >
              <div className="text-center">
                <p className="font-display text-xl text-text-primary">{twin.name}</p>
                <p className="mt-1 text-sm text-text-muted">{twin.ip_address ?? twin.endpoint ?? 'no network telemetry'}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  )
}
