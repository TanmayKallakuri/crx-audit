import type { AnalysisReport } from '../types'
import { downloadReport } from '../utils/report-export'
import { Download } from 'lucide-react'

interface OverviewCardProps {
  report: AnalysisReport
}

export default function OverviewCard({ report }: OverviewCardProps) {
  const { metadata, summary, manifestVersionAnalysis } = report

  const severityCounts = [
    { label: 'CRITICAL', value: summary.criticalPermissions, color: 'bg-red-500', text: 'text-red-400' },
    { label: 'HIGH', value: summary.highPermissions, color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'COMBOS', value: summary.combinationsFound, color: 'bg-amber-500', text: 'text-amber-400' },
    { label: 'CSP', value: summary.cspFindings, color: 'bg-yellow-500', text: 'text-yellow-400' },
    { label: 'CODE', value: summary.codePatterns, color: 'bg-blue-500', text: 'text-blue-400' },
    { label: 'HOST', value: summary.hostFindings, color: 'bg-purple-500', text: 'text-purple-400' },
  ]

  const totalFindings = summary.criticalPermissions + summary.highPermissions + summary.combinationsFound
  const maxBar = Math.max(totalFindings, 1)

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      {/* Severity gradient bar */}
      <div className="h-1 w-full flex">
        {totalFindings > 0 ? (
          <>
            {summary.criticalPermissions > 0 && (
              <div
                className="h-full bg-red-500"
                style={{ width: `${(summary.criticalPermissions / maxBar) * 100}%` }}
              />
            )}
            {summary.highPermissions > 0 && (
              <div
                className="h-full bg-orange-500"
                style={{ width: `${(summary.highPermissions / maxBar) * 100}%` }}
              />
            )}
            {summary.combinationsFound > 0 && (
              <div
                className="h-full bg-amber-500"
                style={{ width: `${(summary.combinationsFound / maxBar) * 100}%` }}
              />
            )}
            <div className="flex-1 bg-[var(--color-surface-3)]" />
          </>
        ) : (
          <div className="flex-1 bg-emerald-500/50" />
        )}
      </div>

      <div className="p-6">
        {/* Header row */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="font-display font-bold text-xl tracking-tight text-[var(--color-text-primary)]">
              {metadata.extensionName || 'Unknown Extension'}
            </h2>
            <div className="flex items-center gap-2 mt-1.5 text-[12px] font-mono text-[var(--color-text-tertiary)]">
              <span>v{metadata.version || '—'}</span>
              <span className="text-[var(--color-border)]">/</span>
              <span>MV{metadata.manifestVersion}</span>
              <span className="text-[var(--color-border)]">/</span>
              <span>{new Date(metadata.analyzedAt).toLocaleDateString()}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadReport(report)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-mono font-medium bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] hover:border-[var(--color-text-tertiary)] transition-all"
            >
              <Download className="w-3 h-3" />
              Export
            </button>
            <div className={`px-3 py-1.5 rounded-md text-[11px] font-mono font-medium ${
              manifestVersionAnalysis.risk === 'medium'
                ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
                : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
            }`}>
              MV{metadata.manifestVersion}
            </div>
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-px bg-[var(--color-border-subtle)] rounded-lg overflow-hidden">
          {severityCounts.map((stat) => (
            <div key={stat.label} className="bg-[var(--color-surface-0)] p-3 text-center">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <div className={`w-1.5 h-1.5 rounded-full ${stat.value > 0 ? stat.color : 'bg-zinc-700'}`} />
                <span className={`text-lg font-display font-bold ${stat.value > 0 ? stat.text : 'text-zinc-600'}`}>
                  {stat.value}
                </span>
              </div>
              <span className="text-[10px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider">
                {stat.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
