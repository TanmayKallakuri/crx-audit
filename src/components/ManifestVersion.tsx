import type { ManifestVersionFinding } from '../types'
import { riskDot } from '../utils/helpers'
import { FileCode } from 'lucide-react'

interface ManifestVersionProps {
  finding: ManifestVersionFinding
}

export default function ManifestVersion({ finding }: ManifestVersionProps) {
  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--color-border-subtle)] flex items-center gap-2">
        <FileCode className="w-3.5 h-3.5 text-[var(--color-text-tertiary)]" />
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Manifest Version
        </h3>
      </div>

      <div className="p-5">
        <div className="flex items-center gap-3 mb-3">
          <div className={`w-2 h-2 rounded-full ${riskDot(finding.risk)}`} />
          <span className={`font-mono text-[13px] ${
            finding.risk === 'medium' ? 'text-amber-400' : 'text-emerald-400'
          }`}>
            Manifest V{finding.manifestVersion}
          </span>
          <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] uppercase">
            {finding.risk === 'none' || finding.risk === 'low' ? 'Current' : 'Deprecated'}
          </span>
        </div>

        <p className="text-[13px] text-[var(--color-text-secondary)] mb-3 leading-relaxed">
          {finding.description}
        </p>

        {finding.details.length > 0 && (
          <ul className="space-y-1.5 pl-5">
            {finding.details.map((detail, i) => (
              <li
                key={i}
                className="text-[12px] text-[var(--color-text-tertiary)] leading-relaxed relative before:content-[''] before:absolute before:left-[-12px] before:top-[8px] before:w-1 before:h-1 before:rounded-full before:bg-[var(--color-text-tertiary)]/40"
              >
                {detail}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
