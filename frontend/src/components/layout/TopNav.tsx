import { NavLink } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/applications', label: 'Applications' },
  { to: '/vulnerabilities', label: 'Vulnerabilities' },
  { to: '/twins', label: 'Digital Twins' },
  { to: '/approvals', label: 'Human Approvals' },
  { to: '/reports', label: 'Reports' },
  { to: '/system-health', label: 'System Health' },
]

export function TopNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-station-border bg-station-hull/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-neon-blue to-neon-purple text-sm font-bold text-white shadow-[0_0_16px_-2px_rgba(77,124,255,0.8)]">
            AT
          </div>
          <span className="font-display text-sm font-bold tracking-widest text-text-primary">
            AUTOSEC<span className="text-neon-cyan">TWIN</span>
          </span>
        </div>
        <nav className="hidden items-center gap-1 lg:flex">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `rounded-md px-3 py-1.5 text-xs font-medium uppercase tracking-wide transition-colors ${
                  isActive
                    ? 'bg-neon-cyan/10 text-neon-cyan'
                    : 'text-text-muted hover:bg-station-panel hover:text-text-primary'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  )
}
