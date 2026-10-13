import type { ImpactLevel } from '../api/types'
import { SEVERITY_DOT, SEVERITY_LABEL } from './severityStyles'

/**
 * `ImpactLevel` (`low`/`medium`/`high`/`critical`) rendered with the app's
 * fixed status palette (`index.css`'s `--color-severity-*` tokens) -- a dot
 * swatch plus the word itself, never color alone, since `warning`/`serious`
 * are deliberately sub-3:1 text contrast on a light surface (dataviz
 * skill's own documented tradeoff) and rely on the label for legibility.
 * `null` means "not yet assessed" (no successful `threat_reasoning` trace
 * for this incident yet), shown as its own honest neutral state rather
 * than defaulting to "low."
 */
export type Severity = ImpactLevel | null

export function SeverityBadge({ severity }: { severity: Severity }) {
  if (severity === null) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 dark:text-gray-500">
        <span className="h-2 w-2 shrink-0 rounded-full bg-gray-300 dark:bg-gray-600" aria-hidden="true" />
        Not yet assessed
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-700 dark:text-gray-200">
      <span className={`h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[severity]}`} aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  )
}
