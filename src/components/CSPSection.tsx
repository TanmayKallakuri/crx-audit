import type { CSPAnalysisResult } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface CSPSectionProps {
  csp: CSPAnalysisResult
}

export default function CSPSection({ csp }: CSPSectionProps) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-gray-100 mb-4">
        Content Security Policy
        {csp.findings.length > 0 && (
          <span className="text-sm font-normal text-gray-500 ml-2">
            ({csp.findings.length} finding{csp.findings.length !== 1 ? 's' : ''})
          </span>
        )}
      </h3>

      {/* Raw CSP */}
      <div className="mb-4">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 font-medium">
          Raw CSP
        </p>
        <pre className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-3 text-sm text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap break-all">
          {csp.raw || '(none specified)'}
        </pre>
      </div>

      {csp.isDefault && (
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg px-4 py-3 text-sm text-blue-400 mb-4">
          No custom CSP defined. Chrome enforces the default Content Security Policy for MV{csp.manifestVersion} extensions.
        </div>
      )}

      {/* Findings */}
      {csp.findings.length > 0 && (
        <div className="space-y-3">
          {csp.findings.map((finding, i) => (
            <div
              key={i}
              className="flex items-start gap-3 bg-gray-950 border border-gray-800 rounded-lg px-4 py-3"
            >
              <span
                className={`mt-0.5 px-2 py-0.5 text-xs font-medium rounded-full border shrink-0 ${riskColor(finding.risk)}`}
              >
                {riskLabel(finding.risk)}
              </span>
              <div>
                <p className="text-sm text-gray-200">{finding.description}</p>
                {finding.detail && (
                  <p className="text-xs text-gray-500 mt-1">{finding.detail}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {csp.findings.length === 0 && !csp.isDefault && (
        <p className="text-sm text-gray-500">No CSP issues found.</p>
      )}
    </div>
  )
}
