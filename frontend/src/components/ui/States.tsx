import type { ReactNode } from 'react'
import { Button } from './Button'

export function LoadingState({ label = 'Loading telemetry...' }: { label?: string }) {
  return (
    <div className="panel scan-line flex flex-col items-center justify-center gap-3 p-12 text-center">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-neon-cyan border-t-transparent" />
      <p className="font-display text-sm text-text-muted">{label}</p>
    </div>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="panel flex flex-col items-center gap-2 p-12 text-center">
      <div className="mb-2 text-3xl opacity-40">&#9711;</div>
      <h3 className="font-display text-sm font-semibold text-text-primary">{title}</h3>
      {description && <p className="max-w-md text-sm text-text-muted">{description}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="panel flex flex-col items-center gap-3 border-alert-critical/40 p-10 text-center">
      <div className="text-2xl text-alert-critical">&#9888;</div>
      <h3 className="font-display text-sm font-semibold text-alert-critical">Transmission failed</h3>
      <p className="max-w-md text-sm text-text-muted">{message}</p>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}

export function Unavailable({ label }: { label?: string }) {
  return <span className="text-sm italic text-text-muted">{label ?? 'Unavailable'}</span>
}
