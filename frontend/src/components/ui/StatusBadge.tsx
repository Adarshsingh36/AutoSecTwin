type Tone = 'verified' | 'critical' | 'warning' | 'progress' | 'neutral'

/**
 * Every status string this app displays, across Twin/Validation/Approval/
 * Remediation/OrchestrationJob, mapped to a visual tone. Unknown statuses
 * fall back to "neutral" rather than guessing -- never silently implied
 * as "good" or "bad".
 */
const STATUS_TONE: Record<string, Tone> = {
  // Verified / healthy / success
  verified: 'verified',
  validated: 'verified',
  approved: 'verified',
  healthy: 'verified',
  ready: 'verified',
  running: 'verified',
  completed: 'verified',
  executed: 'verified',
  not_exploitable: 'verified',
  successful: 'verified',

  // Critical / failed / negative
  failed: 'critical',
  rejected: 'critical',
  unhealthy: 'critical',
  destroyed: 'critical',
  error: 'critical',

  // In-progress
  queued: 'progress',
  executing: 'progress',
  revalidating: 'progress',
  pending: 'progress',
  requested: 'progress',
  provisioning: 'progress',
  creating: 'progress',

  // Needs attention but not a hard failure
  inconclusive: 'warning',
  manual_action_required: 'warning',
  degraded: 'warning',
  unknown: 'warning',

  // Neutral / informational
  planned: 'neutral',
  recommended: 'neutral',
  applied: 'neutral',
}

const TONE_CLASSES: Record<Tone, string> = {
  verified: 'bg-verified-green/15 text-verified-green border-verified-green/40',
  critical: 'bg-alert-critical/15 text-alert-critical border-alert-critical/40',
  warning: 'bg-alert-warning/15 text-alert-warning border-alert-warning/40',
  progress: 'bg-neon-blue/15 text-neon-blue border-neon-blue/40',
  neutral: 'bg-station-border/40 text-text-muted border-station-border',
}

export function StatusBadge({ status, className = '' }: { status: string | null | undefined; className?: string }) {
  const normalized = (status ?? 'unknown').toLowerCase()
  const tone = STATUS_TONE[normalized] ?? 'neutral'
  const label = normalized.replace(/_/g, ' ')

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${TONE_CLASSES[tone]} ${className}`}
    >
      {tone === 'progress' && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
      )}
      {label}
    </span>
  )
}
