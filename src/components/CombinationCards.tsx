import type { PermissionCombination } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface CombinationCardsProps {
  combinations: PermissionCombination[]
}

export default function CombinationCards({ combinations }: CombinationCardsProps) {
  if (combinations.length === 0) return null

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-gray-100">
        Dangerous Combinations
        <span className="text-sm font-normal text-gray-500 ml-2">({combinations.length})</span>
      </h3>

      {combinations.map((combo, i) => (
        <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <h4 className="text-sm font-semibold text-gray-100">{combo.title}</h4>
            <span
              className={`px-2.5 py-0.5 text-xs font-medium rounded-full border ${riskColor(combo.risk)}`}
            >
              {riskLabel(combo.risk)}
            </span>
          </div>

          <div className="flex flex-wrap gap-2 mb-3">
            {combo.permissions.map((perm) => (
              <span
                key={perm}
                className="px-2 py-0.5 text-xs font-mono bg-gray-800 text-gray-300 rounded"
              >
                {perm}
              </span>
            ))}
          </div>

          <p className="text-sm text-gray-400 mb-3">{combo.description}</p>

          <div className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-3">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1 font-medium">
              Real-world example
            </p>
            <p className="text-sm text-gray-400">{combo.realWorldExample}</p>
          </div>
        </div>
      ))}
    </div>
  )
}
