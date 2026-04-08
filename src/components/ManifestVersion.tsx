import type { ManifestVersionFinding } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface ManifestVersionProps {
  finding: ManifestVersionFinding
}

export default function ManifestVersion({ finding }: ManifestVersionProps) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-100">
          Manifest Version
        </h3>
        <span
          className={`px-2.5 py-0.5 text-xs font-medium rounded-full border ${riskColor(finding.risk)}`}
        >
          MV{finding.manifestVersion} — {riskLabel(finding.risk)}
        </span>
      </div>

      <p className="text-sm text-gray-400 mb-4">{finding.description}</p>

      {finding.details.length > 0 && (
        <ul className="space-y-2">
          {finding.details.map((detail, i) => (
            <li
              key={i}
              className="flex items-start gap-2 text-sm text-gray-400"
            >
              <span className="text-gray-600 mt-0.5 shrink-0">&#8226;</span>
              {detail}
            </li>
          ))}
        </ul>
      )}

      {finding.manifestVersion === 2 && (
        <div className="mt-4 bg-orange-500/10 border border-orange-500/20 rounded-lg px-4 py-3 text-sm text-orange-400">
          Manifest V2 is deprecated. Google is phasing out MV2 extensions — this extension should migrate to MV3 for continued Chrome Web Store support and improved security.
        </div>
      )}
    </div>
  )
}
