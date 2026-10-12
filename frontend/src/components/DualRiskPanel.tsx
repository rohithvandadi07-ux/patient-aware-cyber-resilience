import type { RiskScore } from '../api/types'
import { Panel } from './Panel'

/**
 * The Phase 10 gate component (Section 16 / Section 19): cyber risk and
 * clinical risk rendered as two panels of identical shape, side by side,
 * neither one visually subordinate to the other -- "never cyber-risk-as-
 * headline." Both feed a single Decision panel underneath, which is where
 * the two scores actually get compared (per-action `response_impact`),
 * rather than either risk panel editorializing about the other.
 *
 * `riskScore` is `null` whenever the real deterministic Risk Engine
 * (`POST /risk-assessments`) hasn't actually been run for this incident yet
 * -- the backend never persists a `RiskScore` (architecture spec Section 8
 * lists no such table), so there is nothing to show until someone supplies
 * real `ThreatAssessment`/`ClinicalContext`/candidate-action data and gets a
 * real score back. `missingSteps` names which real upstream agent traces
 * are still absent, so the empty state says exactly what hasn't happened
 * yet instead of a generic "no data."
 */

function RiskMeter({ label, value, barClass }: { label: string; value: number; barClass: string }) {
  const percent = Math.round(value * 100)
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-sm text-gray-600 dark:text-gray-300">{label}</span>
        <span className="text-2xl font-semibold tabular-nums">{percent}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-gray-100 dark:bg-gray-800">
        <div
          className={`h-2 rounded-full ${barClass}`}
          style={{ width: `${percent}%` }}
          role="progressbar"
          aria-label={label}
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
    </div>
  )
}

function NotAssessedNotice({ missingSteps }: { missingSteps: string[] }) {
  return (
    <p className="text-sm text-gray-500 dark:text-gray-400">
      Not yet assessed.{' '}
      {missingSteps.length > 0 ? (
        <>
          Waiting on real agent output for: <span className="font-medium">{missingSteps.join(', ')}</span>.
        </>
      ) : (
        'Run the risk assessment for this incident to see real scores here.'
      )}
    </p>
  )
}

export function DualRiskPanel({
  riskScore,
  missingSteps,
}: {
  riskScore: RiskScore | null
  missingSteps: string[]
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Cyber Risk" accent="border-cyber-500">
          {riskScore ? (
            <RiskMeter label="Cyber risk score" value={riskScore.cyber_risk} barClass="bg-cyber-600" />
          ) : (
            <NotAssessedNotice missingSteps={missingSteps} />
          )}
        </Panel>
        <Panel title="Clinical Risk" accent="border-clinical-500">
          {riskScore ? (
            <RiskMeter label="Clinical risk score" value={riskScore.clinical_risk} barClass="bg-clinical-600" />
          ) : (
            <NotAssessedNotice missingSteps={missingSteps} />
          )}
        </Panel>
      </div>

      <Panel title="Decision">
        {riskScore ? (
          <div className="space-y-3">
            <p className="text-sm text-gray-700 dark:text-gray-300">{riskScore.explanation}</p>
            {Object.keys(riskScore.response_impact).length > 0 && (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-gray-500 dark:border-gray-800 dark:text-gray-400">
                    <th className="py-1 pr-4 font-medium">Candidate action</th>
                    <th className="py-1 pr-4 font-medium">Clinical/operational impact</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(riskScore.response_impact).map(([action, impact]) => (
                    <tr key={action} className="border-b border-gray-100 last:border-0 dark:border-gray-800/60">
                      <td className="py-1 pr-4">{action}</td>
                      <td className="py-1 pr-4 capitalize">{impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        ) : (
          <p className="text-sm text-gray-500 dark:text-gray-400">
            No decision context yet -- this fills in once a real cyber risk and clinical risk score exist for this
            incident, comparing the clinical/operational impact of each candidate response action.
          </p>
        )}
      </Panel>
    </div>
  )
}
