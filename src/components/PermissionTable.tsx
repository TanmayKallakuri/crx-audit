import type { PermissionInfo } from '../types'
import { riskDot, riskLabel } from '../utils/helpers'

interface PermissionTableProps {
  permissions: PermissionInfo[]
}

export default function PermissionTable({ permissions }: PermissionTableProps) {
  if (permissions.length === 0) return null

  const order = { critical: 0, high: 1, medium: 2, low: 3, none: 4 }
  const sorted = [...permissions].sort((a, b) => order[a.risk] - order[b.risk])

  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--color-border-subtle)]">
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Permissions
          <span className="ml-2 text-[12px] font-mono font-normal text-[var(--color-text-tertiary)]">
            {permissions.length}
          </span>
        </h3>
      </div>
      <div className="divide-y divide-[var(--color-border-subtle)]">
        {sorted.map((perm) => (
          <div key={perm.name} className="flex items-center gap-4 px-5 py-3 hover:bg-[var(--color-surface-2)]/50 transition-colors">
            <div className={`w-2 h-2 rounded-full shrink-0 ${riskDot(perm.risk)}`} />
            <span className="font-mono text-[13px] text-[var(--color-text-primary)] w-44 shrink-0 truncate">
              {perm.name}
            </span>
            <span className="text-[13px] text-[var(--color-text-secondary)] flex-1 truncate">
              {perm.description}
            </span>
            <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] uppercase shrink-0 w-16 text-right">
              {riskLabel(perm.risk)}
            </span>
            {perm.isOptional && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-tertiary)] shrink-0">
                opt
              </span>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
