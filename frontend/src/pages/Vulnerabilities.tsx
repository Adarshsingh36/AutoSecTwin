import { PageShell } from '../components/layout/PageShell'
import { EmptyState, ErrorState, LoadingState, Unavailable } from '../components/ui/States'
import { StatusBadge } from '../components/ui/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { listVulnerabilities } from '../lib/api/vulnerabilities'

export function Vulnerabilities() {
  const { data, loading, error, refetch } = useAsync(listVulnerabilities)

  return (
    <PageShell title="Vulnerability Discovery Log" subtitle="All recorded findings, from manual entry or the orchestration pipeline.">
      {loading && <LoadingState label="Scanning discovery log..." />}
      {error && <ErrorState message={error} onRetry={refetch} />}
      {!loading && !error && (
        data && data.length > 0 ? (
          <div className="panel overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-station-panel-raised text-xs uppercase tracking-wide text-text-muted">
                <tr>
                  <th className="px-4 py-3">CVE</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Exploitability</th>
                  <th className="px-4 py-3">KEV</th>
                  <th className="px-4 py-3">Discovered</th>
                </tr>
              </thead>
              <tbody>
                {data.map((v) => (
                  <tr key={v.id} className="border-t border-station-border/60 hover:bg-station-panel/40">
                    <td className="px-4 py-3 font-mono text-neon-cyan">{v.cve_id}</td>
                    <td className="px-4 py-3 text-text-primary">{v.title ?? <Unavailable />}</td>
                    <td className="px-4 py-3"><StatusBadge status={v.severity ?? 'unknown'} /></td>
                    <td className="px-4 py-3 text-text-muted">{v.cvss_score?.toFixed(1) ?? <Unavailable />}</td>
                    <td className="px-4 py-3 text-text-muted">{(v.exploitability_probability * 100).toFixed(0)}%</td>
                    <td className="px-4 py-3 text-text-muted">{v.kev_listed ? 'Yes' : 'No'}</td>
                    <td className="px-4 py-3 text-text-muted">{new Date(v.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No vulnerabilities recorded" description="Record a finding via the Vulnerabilities API, or register a target application." />
        )
      )}
    </PageShell>
  )
}
