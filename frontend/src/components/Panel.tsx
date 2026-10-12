import type { ReactNode } from 'react'

/** The one card shape every incident-detail sub-panel uses, so the
 * dual-risk panel's "equal visual weight" requirement (Section 16) is a
 * property of shared layout, not something each panel has to remember to
 * replicate. */
export function Panel({
  title,
  accent,
  children,
}: {
  title: string
  /** A left accent bar's color class, e.g. `'border-cyber-500'`. Omit for a
   * neutral panel (Agent Activity, Evidence, etc.) that isn't one side of
   * the dual-risk comparison. */
  accent?: string
  children: ReactNode
}) {
  return (
    <section
      className={`rounded-lg border bg-white p-4 shadow-sm dark:bg-gray-900 ${
        accent ? `border-l-4 ${accent} border-y border-r border-gray-200 dark:border-gray-800` : 'border-gray-200 dark:border-gray-800'
      }`}
    >
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
        {title}
      </h2>
      {children}
    </section>
  )
}
