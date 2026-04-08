import type { HostPermissionFinding } from '../types'
import { riskDot, riskLabel } from '../utils/helpers'
import { Globe } from 'lucide-react'

interface HostPermissionsProps {
  findings: HostPermissionFinding[]
}

export default function HostPermissions({ findings }: HostPermissionsProps) {
  if (findings.length === 0) return null

  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--color-border-subtle)] flex items-center gap-2">
        <Globe className="w-3.5 h-3.5 text-[var(--color-text-tertiary)]" />
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Host Permissions
          <span className="ml-2 text-[12px] font-mono font-normal text-[var(--color-text-tertiary)]">
            {findings.length}
          </span>
        </h3>
      </div>

      <div className="divide-y divide-[var(--color-border-subtle)]">
        {findings.map((finding, i) => (
          <div key={i} className="p-5">
            <div className="flex items-center gap-3 mb-2">
              <div className={`w-2 h-2 rounded-full shrink-0 ${riskDot(finding.risk)}`} />
              <span className="font-mono text-[13px] text-[var(--color-text-primary)]">
                {finding.pattern}
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-tertiary)]">
                {finding.type}
              </span>
              <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] uppercase ml-auto">
                {riskLabel(finding.risk)}
              </span>
            </div>
            <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed pl-5">
              {finding.description}
            </p>
            {finding.suggestion && (
              <p className="text-[12px] text-emerald-500/70 mt-1.5 pl-5 font-mono">
                {finding.suggestion}
              </p>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
