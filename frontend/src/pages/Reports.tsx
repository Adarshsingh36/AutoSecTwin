import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { PageShell } from '../components/layout/PageShell'
import { Button } from '../components/ui/Button'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { listReports } from '../lib/api/reports'

export function Reports() {
  const { data: reports, loading, error, refetch } = useAsync(listReports)
  const [typeFilter, setTypeFilter] = useState<string>('all')

  const types = useMemo(() => {
    if (!reports) return []
    return Array.from(new Set(reports.map((r) => r.report_type)))
  }, [reports])

  const filtered = useMemo(() => {
    if (!reports) return []
    return typeFilter === 'all' ? reports : reports.filter((r) => r.report_type === typeFilter)
  }, [reports, typeFilter])

  return (
    <PageShell
      title="Reports & Evidence"
      subtitle="Closed-loop technical reports, evidence, and verification outcomes."
      actions={
        <Button onClick={refetch}>
          <span className="text-base">&#8635;</span> Get Reports
        </Button>
      }
    >
      {loading && <LoadingState label="Retrieving report archive..." />}
      {error && <ErrorState message={error} onRetry={refetch} />}

      {!loading && !error && (
        <>
          {reports && reports.length > 0 ? (
            <>
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <button
                  onClick={() => setTypeFilter('all')}
                  className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
                    typeFilter === 'all' ? 'border-neon-cyan text-neon-cyan' : 'border-station-border text-text-muted'
                  }`}
                >
                  All
                </button>
                {types.map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
                      typeFilter === t ? 'border-neon-cyan text-neon-cyan' : 'border-station-border text-text-muted'
                    }`}
                  >
                    {t.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>

              <div className="panel overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="bg-station-panel-raised text-xs uppercase tracking-wide text-text-muted">
                    <tr>
                      <th className="px-4 py-3">Report ID</th>
                      <th className="px-4 py-3">Title</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Vulnerability</th>
                      <th className="px-4 py-3">Created</th>
                      <th className="px-4 py-3" />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((r) => (
                      <tr key={r.id} className="border-t border-station-border/60 hover:bg-station-panel/40">
                        <td className="px-4 py-3 font-mono text-text-muted">#{r.id}</td>
                        <td className="px-4 py-3 text-text-primary">{r.title}</td>
                        <td className="px-4 py-3">
                          <StatusBadge status={r.report_type} />
                        </td>
                        <td className="px-4 py-3 text-text-muted">
                          {r.vulnerability_id ? `#${r.vulnerability_id}` : '—'}
                        </td>
                        <td className="px-4 py-3 text-text-muted">{new Date(r.created_at).toLocaleString()}</td>
                        <td className="px-4 py-3 text-right">
                          <Link to={`/reports/${r.id}`} className="text-neon-cyan hover:underline">
                            View →
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <EmptyState
              title="No reports generated yet"
              description="Reports are generated from a remediation's closed-loop evidence. Execute and revalidate a remediation, then generate its report from the Human Approvals center."
              action={
                <Link to="/approvals">
                  <Button variant="secondary">Go to Human Approvals</Button>
                </Link>
              }
            />
          )}
        </>
      )}
    </PageShell>
  )
}
