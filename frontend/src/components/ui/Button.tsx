import type { ButtonHTMLAttributes, ReactNode } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
  loading?: boolean
  children: ReactNode
}

const VARIANT_CLASSES: Record<NonNullable<ButtonProps['variant']>, string> = {
  primary:
    'bg-gradient-to-r from-neon-blue to-neon-cyan text-station-void font-semibold hover:brightness-110 shadow-[0_0_20px_-4px_rgba(53,231,255,0.6)]',
  secondary:
    'bg-station-panel-raised border border-station-border text-text-primary hover:border-neon-cyan/50',
  danger:
    'bg-gradient-to-r from-red-600 to-alert-critical text-white font-semibold hover:brightness-110 shadow-[0_0_20px_-4px_rgba(255,77,94,0.6)]',
  ghost: 'bg-transparent text-text-muted hover:text-text-primary hover:bg-station-panel',
}

export function Button({ variant = 'primary', loading, disabled, children, className = '', ...rest }: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLASSES[variant]} ${className}`}
      {...rest}
    >
      {loading && (
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
      )}
      {children}
    </button>
  )
}
