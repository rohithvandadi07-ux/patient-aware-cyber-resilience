import type { ReactNode } from 'react'

/**
 * A single real number with its label -- the dataviz skill's "a stat tile
 * or hero number" form for when the job is one headline figure, not a
 * comparison across categories. Every value passed in is read straight off
 * a real query result; a tile with nothing real to show renders its
 * `empty` text instead of a zero that would look like a real count.
 */
export function StatTile({
  label,
  value,
  sublabel,
  empty,
  accent,
}: {
  label: string
  value?: ReactNode
  sublabel?: string
  /** Shown instead of `value` when there is nothing real to report yet. */
  empty?: string
  /** A left accent bar's color class, e.g. `'border-danger-500'`. */
  accent?: string
}) {
  return (
    <div
      className={`rounded-lg border bg-white p-4 shadow-sm dark:bg-gray-900 ${
        accent
          ? `border-l-4 ${accent} border-y border-r border-gray-200 dark:border-gray-800`
          : 'border-gray-200 dark:border-gray-800'
      }`}
    >
      <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{label}</p>
      {value !== undefined ? (
        <p className="mt-1 text-2xl font-semibold tabular-nums text-gray-900 dark:text-gray-50">{value}</p>
      ) : (
        <p className="mt-1 text-sm text-gray-400 dark:text-gray-500">{empty ?? 'No data yet'}</p>
      )}
      {sublabel && <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{sublabel}</p>}
    </div>
  )
}
