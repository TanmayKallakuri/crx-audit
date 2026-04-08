import type { PermissionInfo } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface PermissionTableProps {
  permissions: PermissionInfo[]
}

export default function PermissionTable({ permissions }: PermissionTableProps) {
  if (permissions.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-3">Permissions</h3>
        <p className="text-sm text-gray-500">No permissions declared.</p>
      </div>
    )
  }

  // Sort: critical first, then high, medium, low, none
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, none: 4 }
  const sorted = [...permissions].sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk])

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-gray-100 mb-4">
        Permissions
        <span className="text-sm font-normal text-gray-500 ml-2">({permissions.length})</span>
      </h3>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-left">
              <th className="pb-3 pr-4 text-gray-400 font-medium">Permission</th>
              <th className="pb-3 pr-4 text-gray-400 font-medium">Capability</th>
              <th className="pb-3 pr-4 text-gray-400 font-medium">Risk</th>
              <th className="pb-3 text-gray-400 font-medium">Type</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((perm) => (
              <tr key={perm.name} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="py-3 pr-4 font-mono text-gray-200">{perm.name}</td>
                <td className="py-3 pr-4 text-gray-400">{perm.description}</td>
                <td className="py-3 pr-4">
                  <span
                    className={`inline-block px-2.5 py-0.5 text-xs font-medium rounded-full border ${riskColor(perm.risk)}`}
                  >
                    {riskLabel(perm.risk)}
                  </span>
                </td>
                <td className="py-3">
                  <span
                    className={`inline-block px-2 py-0.5 text-xs rounded font-medium ${
                      perm.isOptional
                        ? 'bg-gray-800 text-gray-400'
                        : 'bg-blue-500/15 text-blue-400'
                    }`}
                  >
                    {perm.isOptional ? 'Optional' : 'Required'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
