import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

interface MissionCardProps {
  title: string
  subtitle?: string
  icon?: ReactNode
  children?: ReactNode
  to?: string
  onClick?: () => void
  accent?: 'cyan' | 'purple' | 'critical' | 'none'
  className?: string
}

const ACCENT_BORDER: Record<NonNullable<MissionCardProps['accent']>, string> = {
  cyan: 'hover:border-neon-cyan/60 hover:shadow-[0_0_0_1px_rgba(53,231,255,0.15),0_12px_40px_-12px_rgba(53,231,255,0.35)]',
  purple: 'hover:border-neon-purple/60 hover:shadow-[0_0_0_1px_rgba(160,107,255,0.15),0_12px_40px_-12px_rgba(160,107,255,0.35)]',
  critical: 'hover:border-alert-critical/60 hover:shadow-[0_0_0_1px_rgba(255,77,94,0.15),0_12px_40px_-12px_rgba(255,77,94,0.35)]',
  none: '',
}

export function MissionCard({
  title,
  subtitle,
  icon,
  children,
  to,
  onClick,
  accent = 'cyan',
  className = '',
}: MissionCardProps) {
  const content = (
    <div
      className={`panel panel-glow group relative flex flex-col gap-3 p-5 transition-all duration-200 ${ACCENT_BORDER[accent]} ${
        to || onClick ? 'cursor-pointer' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-display text-sm font-semibold tracking-wide text-text-primary">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>}
        </div>
        {icon && <div className="text-neon-cyan opacity-80 transition-opacity group-hover:opacity-100">{icon}</div>}
      </div>
      {children}
    </div>
  )

  if (to) {
    return (
      <Link to={to} className="block">
        {content}
      </Link>
    )
  }

  if (onClick) {
    return (
      <button type="button" onClick={onClick} className="block w-full text-left">
        {content}
      </button>
    )
  }

  return content
}

export function MetricTile({ label, value, tone = 'cyan' }: { label: string; value: string | number; tone?: 'cyan' | 'purple' | 'critical' | 'warning' | 'green' }) {
  const toneClass: Record<string, string> = {
    cyan: 'text-neon-cyan',
    purple: 'text-neon-purple',
    critical: 'text-alert-critical',
    warning: 'text-alert-warning',
    green: 'text-verified-green',
  }
  return (
    <div className="panel flex flex-col gap-1 p-4">
      <span className="text-xs uppercase tracking-wider text-text-muted">{label}</span>
      <span className={`font-display text-2xl font-bold ${toneClass[tone]}`}>{value}</span>
    </div>
  )
}
