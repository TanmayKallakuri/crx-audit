import type { HostPermissionFinding } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface HostPermissionsProps {
  findings: HostPermissionFinding[]
}

export default function HostPermissions({ findings }: HostPermissionsProps) {
  if (findings.length === 0) return null

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-gray-100 mb-4">
        Host Permissions
        <span className="text-sm font-normal text-gray-500 ml-2">({findings.length})</span>
      </h3>

      <div className="space-y-3">
        {findings.map((finding, i) => (
          <div
            key={i}
            className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-3"
          >
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-gray-200">{finding.pattern}</span>
                <span className="px-2 py-0.5 text-xs bg-gray-800 text-gray-400 rounded">
                  {finding.type}
                </span>
              </div>
              <span
                className={`px-2.5 py-0.5 text-xs font-medium rounded-full border shrink-0 ${riskColor(finding.risk)}`}
              >
                {riskLabel(finding.risk)}
              </span>
            </div>
            <p className="text-sm text-gray-400">{finding.description}</p>
            {finding.suggestion && (
              <p className="text-xs text-blue-400 mt-2">
                Suggestion: {finding.suggestion}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
