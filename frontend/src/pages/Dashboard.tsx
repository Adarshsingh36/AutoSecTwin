import { useAsync } from '../hooks/useAsync'
import { listVulnerabilities } from '../lib/api/vulnerabilities'
import { listTwins } from '../lib/api/twins'
import { listApprovals } from '../lib/api/approvals'
import { listRemediations } from '../lib/api/remediations'
import { PageShell } from '../components/layout/PageShell'
import { MetricTile, MissionCard } from '../components/ui/MissionCard'
import { LoadingState, ErrorState, Unavailable } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { REMEDIATION_IN_PROGRESS } from '../lib/types'
import { Link } from 'react-router-dom'

export function Dashboard() {
  const vulnerabilities = useAsync(listVulnerabilities)
  const twins = useAsync(listTwins)
  const approvals = useAsync(listApprovals)
  const remediations = useAsync(listRemediations)

  const anyLoading = vulnerabilities.loading || twins.loading || approvals.loading || remediations.loading
  const anyError = vulnerabilities.error || twins.error || approvals.error || remediations.error

  const critical = vulnerabilities.data?.filter((v) => v.severity?.toUpperCase() === 'CRITICAL').length
  const activeTwins = twins.data?.filter((t) => t.status !== 'destroyed').length
  const pendingApprovals = approvals.data?.filter((a) => a.status === 'pending').length
  const inProgress = remediations.data?.filter((r) => REMEDIATION_IN_PROGRESS.has(r.status)).length
  const verified = remediations.data?.filter((r) => r.status === 'verified').length

  return (
    <PageShell
      title="Mission Overview"
      subtitle="Autonomous Security Validation and Remediation — Digital Twin Operations"
    >
      {anyError && (
        <div className="mb-6">
          <ErrorState message="One or more metrics could not be loaded from the backend." />
        </div>
      )}

      {anyLoading ? (
        <LoadingState label="Syncing station telemetry..." />
      ) : (
        <>
          <section className="mb-8 grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-6">
            <MetricTile label="Registered Targets" value={vulnerabilities.data ? new Set(vulnerabilities.data.map((v) => v.asset_id)).size : '—'} />
            <MetricTile label="Vulnerabilities" value={vulnerabilities.data?.length ?? '—'} tone="purple" />
            <MetricTile label="Critical" value={critical ?? '—'} tone="critical" />
            <MetricTile label="Active Twins" value={activeTwins ?? '—'} tone="cyan" />
            <MetricTile label="Pending Approvals" value={pendingApprovals ?? '—'} tone="warning" />
            <MetricTile label="Verified Fixes" value={verified ?? '—'} tone="green" />
          </section>

          <section className="mb-8">
            <h2 className="mb-3 font-display text-sm font-semibold uppercase tracking-wider text-text-muted">
              Quick Actions
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
              <MissionCard title="Register Application" subtitle="Add a new target for assessment" to="/applications" accent="cyan" />
              <MissionCard title="Enter Digital Twin" subtitle="Inspect an isolated environment" to="/twins" accent="purple" />
              <MissionCard title="Review Approvals" subtitle={`${pendingApprovals ?? 0} awaiting decision`} to="/approvals" accent={pendingApprovals ? 'critical' : 'cyan'} />
              <MissionCard title="Get Reports" subtitle="Closed-loop evidence & PDFs" to="/reports" accent="cyan" />
              <MissionCard title="Vulnerabilities" subtitle="Full discovery log" to="/vulnerabilities" accent="purple" />
            </div>
          </section>

          <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="panel p-5">
              <h2 className="mb-4 font-display text-sm font-semibold uppercase tracking-wider text-text-muted">
                Recent Remediation Activity
              </h2>
              {remediations.data && remediations.data.length > 0 ? (
                <ul className="flex flex-col gap-3">
                  {remediations.data.slice(0, 6).map((r) => (
                    <li key={r.id} className="flex items-center justify-between gap-3 border-b border-station-border/60 pb-3 last:border-0 last:pb-0">
                      <div className="min-w-0">
                        <Link to={`/approvals`} className="block truncate text-sm text-text-primary hover:text-neon-cyan">
                          {r.action}
                        </Link>
                        <span className="text-xs text-text-muted">Remediation #{r.id} · Vulnerability #{r.vulnerability_id}</span>
                      </div>
                      <StatusBadge status={r.status} />
                    </li>
                  ))}
                </ul>
              ) : (
                <Unavailable label="No remediation activity recorded yet." />
              )}
            </div>

            <div className="panel p-5">
              <h2 className="mb-4 font-display text-sm font-semibold uppercase tracking-wider text-text-muted">
                Twin Fleet Status
              </h2>
              {twins.data && twins.data.length > 0 ? (
                <ul className="flex flex-col gap-3">
                  {twins.data.slice(0, 6).map((t) => (
                    <li key={t.id} className="flex items-center justify-between gap-3 border-b border-station-border/60 pb-3 last:border-0 last:pb-0">
                      <div className="min-w-0">
                        <Link to="/twins" className="block truncate text-sm text-text-primary hover:text-neon-cyan">
                          {t.name}
                        </Link>
                        <span className="text-xs text-text-muted">{t.twin_image ?? 'image unknown'}</span>
                      </div>
                      <StatusBadge status={t.health ?? t.status} />
                    </li>
                  ))}
                </ul>
              ) : (
                <Unavailable label="No digital twins provisioned yet." />
              )}
              {inProgress ? (
                <p className="mt-4 text-xs text-neon-blue">{inProgress} remediation job(s) currently in progress.</p>
              ) : null}
            </div>
          </section>
        </>
      )}
    </PageShell>
  )
}
