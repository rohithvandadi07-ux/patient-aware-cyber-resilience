import { Link, NavLink, Outlet } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Overview' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/fleet', label: 'Fleet' },
  { to: '/threat-monitor', label: 'Threat Monitor' },
  { to: '/analytics', label: 'Analytics' },
] as const

export function Layout() {
  return (
    <div className="min-h-svh bg-gray-50 text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <header className="border-b border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <Link to="/" className="font-semibold tracking-tight">
            Patient-Aware Cyber Resilience <span className="text-gray-400 dark:text-gray-500">· SOC Dashboard</span>
          </Link>
          <nav aria-label="Primary" className="flex flex-wrap gap-1 text-sm">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `rounded-md px-2.5 py-1.5 font-medium transition-colors ${
                    isActive
                      ? 'bg-cyber-100 text-cyber-700 dark:bg-cyber-900 dark:text-cyber-300'
                      : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
