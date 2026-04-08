import type { PermissionCombination } from '../types'
import { riskColor, riskLabel, riskBorderLeft } from '../utils/helpers'
import { AlertTriangle } from 'lucide-react'

interface CombinationCardsProps {
  combinations: PermissionCombination[]
}

export default function CombinationCards({ combinations }: CombinationCardsProps) {
  if (combinations.length === 0) return null

  return (
    <section>
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-4 h-4 text-amber-500" />
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Dangerous Combinations
          <span className="ml-2 text-[12px] font-mono font-normal text-[var(--color-text-tertiary)]">
            {combinations.length}
          </span>
        </h3>
      </div>

      <div className="grid gap-3">
        {combinations.map((combo, i) => (
          <div
            key={i}
            className={`rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] border-l-[3px] ${riskBorderLeft(combo.risk)} overflow-hidden ${
              combo.risk === 'critical' ? 'glow-critical' : combo.risk === 'high' ? 'glow-high' : ''
            }`}
          >
            <div className="p-5">
              <div className="flex items-start justify-between mb-3">
                <h4 className="font-display font-semibold text-[14px] text-[var(--color-text-primary)]">
                  {combo.title}
                </h4>
                <span className={`px-2 py-0.5 text-[10px] font-mono font-medium rounded border ${riskColor(combo.risk)}`}>
                  {riskLabel(combo.risk)}
                </span>
              </div>

              <div className="flex flex-wrap gap-1.5 mb-3">
                {combo.permissions.map((perm) => (
                  <span
                    key={perm}
                    className="px-2 py-0.5 text-[11px] font-mono bg-[var(--color-surface-0)] text-[var(--color-text-secondary)] rounded border border-[var(--color-border-subtle)]"
                  >
                    {perm}
                  </span>
                ))}
              </div>

              <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed mb-3">
                {combo.description}
              </p>

              <div className="rounded-lg bg-[var(--color-surface-0)] border border-[var(--color-border-subtle)] px-4 py-3">
                <p className="text-[10px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider mb-1.5">
                  Real-world precedent
                </p>
                <p className="text-[12px] text-[var(--color-text-secondary)] leading-relaxed">
                  {combo.realWorldExample}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
