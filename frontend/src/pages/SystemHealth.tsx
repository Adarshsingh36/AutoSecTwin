import { PageShell } from '../components/layout/PageShell'
import { MetricTile } from '../components/ui/MissionCard'
import { ErrorState, LoadingState, Unavailable } from '../components/ui/States'
import { useAsync } from '../hooks/useAsync'
import { getTrustStatistics, listDrift } from '../lib/api/health'

export function SystemHealth() {
  const trust = useAsync(getTrustStatistics)
  const drift = useAsync(listDrift)

  return (
    <PageShell title="System Health" subtitle="AI prediction trust, hallucination tracking, and model drift.">
      {(trust.loading || drift.loading) && <LoadingState label="Running diagnostics..." />}
      {trust.error && <ErrorState message={trust.error} onRetry={trust.refetch} />}

      {!trust.loading && !trust.error && trust.data && (
        <section className="mb-8 grid grid-cols-2 gap-4 md:grid-cols-3">
          <MetricTile label="Total Comparisons" value={trust.data.total_comparisons} />
          <MetricTile label="Hallucinations" value={trust.data.hallucinations} tone="critical" />
          <MetricTile label="Agreement Rate" value={`${(trust.data.agreement_rate * 100).toFixed(1)}%`} tone="green" />
        </section>
      )}

      <section className="panel p-5">
        <h2 className="mb-4 font-display text-sm font-semibold uppercase tracking-wider text-text-muted">Model Drift</h2>
        {drift.error && <ErrorState message={drift.error} onRetry={drift.refetch} />}
        {!drift.loading && !drift.error && (
          drift.data && drift.data.length > 0 ? (
            <ul className="flex flex-col gap-3">
              {drift.data.map((d, i) => (
                <li key={i} className="flex items-center justify-between border-b border-station-border/60 pb-3 last:border-0">
                  <span className="text-sm text-text-primary">{d.model_name}</span>
                  <span className={`text-sm font-semibold ${d.retraining_recommended ? 'text-alert-warning' : 'text-verified-green'}`}>
                    drift {d.drift_score.toFixed(3)} {d.retraining_recommended ? '· retraining recommended' : ''}
                  </span>
                </li>
              ))}
            </ul>
          ) : <Unavailable label="No drift data recorded yet." />
        )}
      </section>
    </PageShell>
  )
}
