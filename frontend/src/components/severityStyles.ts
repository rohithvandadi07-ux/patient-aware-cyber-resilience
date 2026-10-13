import type { ImpactLevel } from '../api/types'

/**
 * The fixed severity status palette (`index.css`'s `--color-severity-*`
 * tokens), shared between `SeverityBadge` and anything that needs the raw
 * class name directly -- e.g. a bar chart row's fill color. Kept in its
 * own module (rather than exported alongside the `SeverityBadge`
 * component) purely so Fast Refresh can still treat `SeverityBadge.tsx`
 * as a component-only file.
 */
export const SEVERITY_DOT: Record<ImpactLevel, string> = {
  low: 'bg-severity-good',
  medium: 'bg-severity-warning',
  high: 'bg-severity-serious',
  critical: 'bg-severity-critical',
}

export const SEVERITY_LABEL: Record<ImpactLevel, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}
