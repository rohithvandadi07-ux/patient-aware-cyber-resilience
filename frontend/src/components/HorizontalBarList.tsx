/**
 * A dependency-free horizontal bar chart: one row per category, bar length
 * scaled to the largest value in the list, the real count always rendered
 * as visible text beside the bar rather than left for color/length alone
 * to carry (dataviz skill: "text wears text tokens... a colored mark
 * beside them carries identity"; values are never hidden inside a tooltip
 * only). A single-series magnitude chart like this needs one accent hue,
 * not a color per bar -- `barClassName` defaults to the app's own primary
 * accent (`cyber-600`) unless a row supplies its own (e.g. a severity or
 * device-health status color), matching the project's existing
 * `RiskMeter` bar styling (`DualRiskPanel.tsx`): 8px rounded track, rounded
 * fill, `role="img"` with a full-sentence `aria-label` so the value is
 * available to assistive tech even though the fill itself is decorative.
 */
export interface BarRow {
  key: string
  label: string
  value: number
  /** Overrides the default accent for this one row, e.g. a severity dot color. */
  barClassName?: string
}

export function HorizontalBarList({
  rows,
  emptyMessage,
  valueFormatter,
}: {
  rows: BarRow[]
  emptyMessage: string
  valueFormatter?: (value: number) => string
}) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500 dark:text-gray-400">{emptyMessage}</p>
  }

  const max = Math.max(...rows.map((row) => row.value), 1)
  const format = valueFormatter ?? ((value: number) => String(value))

  return (
    <ul className="space-y-3">
      {rows.map((row) => {
        const percent = Math.round((row.value / max) * 100)
        return (
          <li key={row.key}>
            <div className="mb-1 flex items-baseline justify-between text-sm">
              <span className="text-gray-700 dark:text-gray-200">{row.label}</span>
              <span className="font-medium tabular-nums text-gray-900 dark:text-gray-50">{format(row.value)}</span>
            </div>
            <div
              className="h-2 w-full rounded-full bg-gray-100 dark:bg-gray-800"
              role="img"
              aria-label={`${row.label}: ${format(row.value)}`}
            >
              <div
                className={`h-2 rounded-full ${row.barClassName ?? 'bg-cyber-600'}`}
                style={{ width: `${percent}%` }}
                aria-hidden="true"
              />
            </div>
          </li>
        )
      })}
    </ul>
  )
}
