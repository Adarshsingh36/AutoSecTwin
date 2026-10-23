import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { PageShell } from '../components/layout/PageShell'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { listTwins } from '../lib/api/twins'

export function Twins() {
  const { data: twins, loading, error, refetch } = useAsync(listTwins)
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    if (!twins) return []
    const q = search.toLowerCase()
    return twins.filter(
      (t) => t.name.toLowerCase().includes(q) || (t.twin_image ?? '').toLowerCase().includes(q) || String(t.id).includes(q),
    )
  }, [twins, search])

  return (
    <PageShell title="Digital Twin Fleet" subtitle="Isolated environments provisioned for exploit validation and remediation.">
      {loading && <LoadingState label="Scanning twin fleet..." />}
      {error && <ErrorState message={error} onRetry={refetch} />}

      {!loading && !error && (
        <>
          {twins && twins.length > 0 ? (
            <>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by name, image, or ID..."
                className="mb-4 w-full max-w-md rounded-lg border border-station-border bg-station-void/60 px-3 py-2 text-sm text-text-primary focus:border-neon-cyan focus:outline-none"
              />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {filtered.map((t) => (
                  <Link
                    key={t.id}
                    to={`/twins/${t.id}`}
                    className="panel panel-glow flex flex-col gap-2 p-4 transition-colors hover:border-neon-cyan/60"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-display text-sm font-semibold text-text-primary">{t.name}</span>
                      <StatusBadge status={t.health ?? t.status} />
                    </div>
                    <span className="truncate text-xs text-text-muted">{t.twin_image ?? 'image unknown'}</span>
                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
                      <span>ID #{t.id}</span>
                      <span>{t.environment ?? 'env n/a'}</span>
                      <span>{t.provider}</span>
                    </div>
                  </Link>
                ))}
              </div>
            </>
          ) : (
            <EmptyState title="No digital twins provisioned yet" description="Provision one via the orchestration pipeline or POST /twins/provision for an existing vulnerability." />
          )}
        </>
      )}
    </PageShell>
  )
}
