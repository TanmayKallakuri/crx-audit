import type { AnalysisReport } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface OverviewCardProps {
  report: AnalysisReport
}

export default function OverviewCard({ report }: OverviewCardProps) {
  const { metadata, summary, manifestVersionAnalysis } = report

  const stats = [
    { label: 'Permissions', value: summary.totalPermissions, risk: 'none' as const },
    { label: 'Critical', value: summary.criticalPermissions, risk: 'critical' as const },
    { label: 'High', value: summary.highPermissions, risk: 'high' as const },
    { label: 'Combos', value: summary.combinationsFound, risk: summary.combinationsFound > 0 ? 'high' as const : 'none' as const },
    { label: 'CSP Issues', value: summary.cspFindings, risk: summary.cspFindings > 0 ? 'medium' as const : 'none' as const },
    { label: 'Code Patterns', value: summary.codePatterns, risk: summary.codePatterns > 0 ? 'medium' as const : 'none' as const },
    { label: 'Host Issues', value: summary.hostFindings, risk: summary.hostFindings > 0 ? 'medium' as const : 'none' as const },
  ]

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">
            {metadata.extensionName || 'Unknown Extension'}
          </h2>
          <div className="flex items-center gap-3 mt-1 text-sm text-gray-400">
            <span>v{metadata.version || '—'}</span>
            <span className="text-gray-700">|</span>
            <span>Manifest V{metadata.manifestVersion}</span>
            <span className="text-gray-700">|</span>
            <span>Analyzed {new Date(metadata.analyzedAt).toLocaleString()}</span>
          </div>
        </div>
        <span
          className={`px-3 py-1 text-xs font-medium rounded-full border ${riskColor(manifestVersionAnalysis.risk)}`}
        >
          MV{metadata.manifestVersion} — {riskLabel(manifestVersionAnalysis.risk)}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-center"
          >
            <div
              className={`text-2xl font-bold ${
                stat.value > 0 && stat.risk !== 'none'
                  ? stat.risk === 'critical'
                    ? 'text-red-400'
                    : stat.risk === 'high'
                      ? 'text-orange-400'
                      : 'text-yellow-400'
                  : 'text-gray-300'
              }`}
            >
              {stat.value}
            </div>
            <div className="text-xs text-gray-500 mt-1">{stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
