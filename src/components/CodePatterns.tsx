import { useState } from 'react'
import type { CodePatternMatch } from '../types'
import { riskColor, riskLabel } from '../utils/helpers'

interface CodePatternsProps {
  patterns: CodePatternMatch[]
}

const categoryLabels: Record<string, string> = {
  sink: 'DOM Sinks',
  source: 'Data Sources',
  network: 'Network',
  obfuscation: 'Obfuscation',
}

const fileTypeLabels: Record<string, string> = {
  'content-script': 'Content Script',
  background: 'Background',
  'web-accessible': 'Web Accessible',
  other: 'Other',
}

export default function CodePatterns({ patterns }: CodePatternsProps) {
  if (patterns.length === 0) return null

  // Group by category
  const grouped = patterns.reduce<Record<string, CodePatternMatch[]>>((acc, p) => {
    if (!acc[p.category]) acc[p.category] = []
    acc[p.category].push(p)
    return acc
  }, {})

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-gray-100">
        Code Patterns
        <span className="text-sm font-normal text-gray-500 ml-2">({patterns.length})</span>
      </h3>

      {Object.entries(grouped).map(([category, items]) => (
        <div key={category} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">
            {categoryLabels[category] || category}
          </h4>
          <div className="space-y-3">
            {items.map((match, i) => (
              <PatternItem key={i} match={match} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function PatternItem({ match }: { match: CodePatternMatch }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`px-2 py-0.5 text-xs font-medium rounded-full border shrink-0 ${riskColor(match.risk)}`}
          >
            {riskLabel(match.risk)}
          </span>
          <span className="text-sm text-gray-200 truncate">{match.description}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0 ml-3">
          <span className="text-xs font-mono text-gray-500">
            {match.filePath}:{match.lineNumber}
          </span>
          <span className="px-1.5 py-0.5 text-xs bg-gray-800 text-gray-400 rounded">
            {fileTypeLabels[match.fileType] || match.fileType}
          </span>
          <span className="text-gray-600 text-xs">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && match.context.length > 0 && (
        <div className="border-t border-gray-800 px-4 py-3 overflow-x-auto">
          <pre className="text-xs font-mono leading-relaxed">
            {match.context.map((line, idx) => {
              const lineNum = match.lineNumber - Math.floor(match.context.length / 2) + idx
              const isMatchLine = lineNum === match.lineNumber
              return (
                <div
                  key={idx}
                  className={`${isMatchLine ? 'bg-yellow-500/10 text-yellow-300' : 'text-gray-500'}`}
                >
                  <span className="inline-block w-10 text-right mr-4 text-gray-600 select-none">
                    {lineNum}
                  </span>
                  {line}
                </div>
              )
            })}
          </pre>
        </div>
      )}
    </div>
  )
}
