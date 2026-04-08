import type { CSPAnalysisResult } from '../types'
import { riskColor, riskLabel, riskDot } from '../utils/helpers'
import { Lock } from 'lucide-react'

interface CSPSectionProps {
  csp: CSPAnalysisResult
}

export default function CSPSection({ csp }: CSPSectionProps) {
  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--color-border-subtle)] flex items-center gap-2">
        <Lock className="w-3.5 h-3.5 text-[var(--color-text-tertiary)]" />
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Content Security Policy
          {csp.findings.length > 0 && (
            <span className="ml-2 text-[12px] font-mono font-normal text-[var(--color-text-tertiary)]">
              {csp.findings.length} findings
            </span>
          )}
        </h3>
      </div>

      <div className="p-5 space-y-4">
        <div>
          <p className="text-[10px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider mb-2">
            {csp.isDefault ? 'Default CSP (Chrome-enforced)' : 'Declared CSP'}
          </p>
          <pre className="text-[12px] font-mono text-[var(--color-text-secondary)] bg-[var(--color-surface-0)] border border-[var(--color-border-subtle)] rounded-lg p-3 overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
            {csp.raw || "script-src 'self'; object-src 'self'"}
          </pre>
        </div>

        {csp.findings.length > 0 && (
          <div className="space-y-2">
            {csp.findings.map((finding, i) => (
              <div key={i} className="flex items-start gap-3 rounded-lg bg-[var(--color-surface-0)] border border-[var(--color-border-subtle)] p-3">
                <div className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${riskDot(finding.risk)}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-1.5 py-0.5 text-[10px] font-mono font-medium rounded border ${riskColor(finding.risk)}`}>
                      {riskLabel(finding.risk)}
                    </span>
                  </div>
                  <p className="text-[13px] text-[var(--color-text-primary)] leading-relaxed">{finding.description}</p>
                  {finding.detail && (
                    <p className="text-[12px] text-[var(--color-text-tertiary)] mt-1 leading-relaxed">{finding.detail}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {csp.findings.length === 0 && (
          <p className="text-[13px] text-emerald-500/70 font-mono">No CSP issues found.</p>
        )}
      </div>
    </section>
  )
}
